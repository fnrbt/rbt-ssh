module Program

open System
open System.Text
open System.Net.Sockets
open System.Collections.Concurrent
open Ssh

// Rot13 transformation
let rot13 (s: string) =
    s |> String.map (fun c ->
        match c with
        | c when c >= 'a' && c <= 'z' -> char ((int c - int 'a' + 13) % 26 + int 'a')
        | c when c >= 'A' && c <= 'Z' -> char ((int c - int 'A' + 13) % 26 + int 'A')
        | _ -> c
    )

// Channel state for rot13 shell
type ShellState = {
    Buffer: StringBuilder
    Stream: NetworkStream
    Context: SessionContext ref
    LocalChannel: uint32
}

// Active shells
let activeShells = ConcurrentDictionary<uint32, ShellState>()

// Send data to a channel
let sendToChannel (state: ShellState) (data: string) = async {
    let bytes = Encoding.UTF8.GetBytes(data)
    let ctx = !state.Context
    match Channel.ChannelManager.getChannel ctx.ChannelManager state.LocalChannel with
    | Some channel ->
        let dataMsg = ChannelData(channel.RemoteChannel, bytes)
        let! result = Transport.sendMessage state.Stream ctx.TransportState dataMsg
        match result with
        | Ok newTransportState ->
            state.Context := { ctx with TransportState = newTransportState }
        | Error _ -> ()
    | None -> ()
}

// Send prompt
let sendPrompt state = async {
    do! sendToChannel state "rot13> "
}

// Process a line of input
let processLine (state: ShellState) (line: string) = async {
    let trimmed = line.TrimEnd([| '\r'; '\n' |])
    if trimmed = "exit" || trimmed = "quit" then
        do! sendToChannel state "Goodbye!\r\n"
        // Close the channel
        let ctx = !state.Context
        match Channel.ChannelManager.getChannel ctx.ChannelManager state.LocalChannel with
        | Some _channel ->
            // Send exit status - update context after each send
            let! statusResult = Channel.sendExitStatus state.Stream ctx.TransportState ctx.ChannelManager state.LocalChannel 0u
            match statusResult with
            | Ok newTransport -> state.Context := { !state.Context with TransportState = newTransport }
            | Error _ -> ()

            // Send EOF
            let ctx2 = !state.Context
            let! eofResult = Channel.sendChannelEof state.Stream ctx2.TransportState ctx2.ChannelManager state.LocalChannel
            match eofResult with
            | Ok newTransport -> state.Context := { !state.Context with TransportState = newTransport }
            | Error _ -> ()

            // Close channel
            let ctx3 = !state.Context
            let! closeResult = Channel.closeChannel state.Stream ctx3.TransportState ctx3.ChannelManager state.LocalChannel
            match closeResult with
            | Ok newTransport -> state.Context := { !state.Context with TransportState = newTransport }
            | Error _ -> ()
        | None -> ()
    else
        let result = rot13 trimmed
        do! sendToChannel state (result + "\r\n")
        do! sendPrompt state
}

// Handle incoming data
let handleData (channelId: uint32) (data: byte[]) = async {
    match activeShells.TryGetValue(channelId) with
    | true, state ->
        let text = Encoding.UTF8.GetString(data)

        // Echo the input back (for terminal)
        do! sendToChannel state text

        for c in text do
            if c = '\r' || c = '\n' then
                let line = state.Buffer.ToString()
                state.Buffer.Clear() |> ignore
                if line.Length > 0 then
                    do! sendToChannel state "\r\n"
                    do! processLine state line
            elif c = '\x7f' || c = '\b' then  // Backspace/DEL
                if state.Buffer.Length > 0 then
                    state.Buffer.Remove(state.Buffer.Length - 1, 1) |> ignore
                    // Send backspace sequence to terminal
                    do! sendToChannel state "\b \b"
            elif c = '\x03' then  // Ctrl+C
                do! sendToChannel state "^C\r\n"
                do! sendPrompt state
                state.Buffer.Clear() |> ignore
            elif c >= ' ' then
                state.Buffer.Append(c) |> ignore
    | false, _ -> ()
}

// Run the server with a custom session handler
let runServer () =
    let hostKey = Crypto.createEd25519HostKey()

    let config = {
        ServerConfig.defaults with
            ListenPort = 2222
            HostKeys = [ hostKey ]
    }

    printfn "SSH Rot13 Server"
    printfn "================"
    printfn "Listening on port 2222"
    printfn "Connect with: ssh -o StrictHostKeyChecking=no -p 2222 user@localhost"
    printfn "Any username/password will work"
    printfn ""

    let listener = new TcpListener(System.Net.IPAddress.Any, 2222)
    listener.Start()

    let rec acceptLoop () = async {
        let! client = listener.AcceptTcpClientAsync() |> Async.AwaitTask
        printfn "New connection from %s" (client.Client.RemoteEndPoint.ToString())

        // Handle client in background
        Async.Start(handleClient client)

        return! acceptLoop ()
    }

    and handleClient (client: TcpClient) = async {
        use client = client
        use stream = client.GetStream()

        try
            // Version exchange
            let! versionResult = Transport.exchangeVersions stream config.ServerVersion
            match versionResult with
            | Error e ->
                printfn "Version exchange failed: %A" e
            | Ok clientVersion ->
                printfn "Client version: %s" clientVersion

                let transportState = {
                    TransportState.create config.ServerVersion with
                        ClientVersion = Some clientVersion
                }

                // Key exchange
                let! kexResult = KeyExchange.handleKeyExchange stream transportState config.HostKeys
                match kexResult with
                | Error e ->
                    printfn "Key exchange failed: %A" e
                | Ok (transportAfterKex, kexState, _) ->
                    printfn "Key exchange complete"

                    match kexState.SessionId with
                    | None ->
                        printfn "No session ID"
                    | Some sessionId ->
                        // Authentication
                        let authCallbacks = {
                            ValidatePassword = fun user _password -> async {
                                printfn "Password auth for user: %s" user
                                return Accepted
                            }
                            ValidatePublicKey = fun _user _alg _key -> async {
                                return Rejected
                            }
                        }

                        let! authResult = Auth.runAuthLoop stream transportAfterKex sessionId authCallbacks 10
                        match authResult with
                        | Error e ->
                            printfn "Auth failed: %A" e
                        | Ok (transportAfterAuth, authState) ->
                            printfn "User authenticated: %s" (authState.Username |> Option.defaultValue "unknown")

                            // Create session context
                            let ctx = ref {
                                TransportState = transportAfterAuth
                                KexState = kexState
                                ChannelManager = Channel.ChannelManager.create()
                                AuthState = Some authState
                                State = SessionState.Authenticated
                                Username = authState.Username
                            }

                            // Channel callbacks
                            let channelCallbacks = {
                                OnData = handleData
                                OnExtendedData = fun _ _ _ -> async { () }
                                OnEof = fun channelId -> async {
                                    printfn "EOF on channel %d" channelId
                                    activeShells.TryRemove(channelId) |> ignore
                                }
                                OnClose = fun channelId -> async {
                                    printfn "Channel %d closed" channelId
                                    activeShells.TryRemove(channelId) |> ignore
                                }
                                OnPtyRequest = fun channelId term _ _ -> async {
                                    printfn "PTY request on channel %d: %s" channelId term
                                    return true
                                }
                                OnShellRequest = fun channelId -> async {
                                    printfn "Shell request on channel %d" channelId

                                    // Create shell state
                                    let shellState = {
                                        Buffer = StringBuilder()
                                        Stream = stream
                                        Context = ctx
                                        LocalChannel = channelId
                                    }
                                    activeShells.[channelId] <- shellState

                                    // Send welcome and prompt
                                    do! sendToChannel shellState "Welcome to the Rot13 Shell!\r\n"
                                    do! sendToChannel shellState "Type text and press Enter to see it rot13'd.\r\n"
                                    do! sendToChannel shellState "Type 'exit' or 'quit' to disconnect.\r\n"
                                    do! sendToChannel shellState "\r\n"
                                    do! sendPrompt shellState

                                    return true
                                }
                                OnExecRequest = fun channelId command -> async {
                                    printfn "Exec request on channel %d: %s" channelId command

                                    // Just rot13 the command and return
                                    let result = rot13 command
                                    let currentCtx = !ctx
                                    match Channel.ChannelManager.getChannel currentCtx.ChannelManager channelId with
                                    | Some channel ->
                                        let bytes = Encoding.UTF8.GetBytes(result + "\n")
                                        let dataMsg = ChannelData(channel.RemoteChannel, bytes)
                                        let! sendResult = Transport.sendMessage stream currentCtx.TransportState dataMsg
                                        match sendResult with
                                        | Ok newTransport -> ctx := { !ctx with TransportState = newTransport }
                                        | Error _ -> ()

                                        // Send exit status and close - update ctx after each send
                                        let! statusResult = Channel.sendExitStatus stream (!ctx).TransportState (!ctx).ChannelManager channelId 0u
                                        match statusResult with
                                        | Ok newTransport -> ctx := { !ctx with TransportState = newTransport }
                                        | Error _ -> ()

                                        let! eofResult = Channel.sendChannelEof stream (!ctx).TransportState (!ctx).ChannelManager channelId
                                        match eofResult with
                                        | Ok newTransport -> ctx := { !ctx with TransportState = newTransport }
                                        | Error _ -> ()

                                        let! closeResult = Channel.closeChannel stream (!ctx).TransportState (!ctx).ChannelManager channelId
                                        match closeResult with
                                        | Ok newTransport -> ctx := { !ctx with TransportState = newTransport }
                                        | Error _ -> ()
                                    | None -> ()

                                    return true
                                }
                            }

                            // Message loop
                            let rec messageLoop () = async {
                                let currentCtx = !ctx
                                if currentCtx.State = SessionState.Disconnected then
                                    return ()
                                else
                                    try
                                        let! result = Transport.receiveMessage stream currentCtx.TransportState
                                        match result with
                                        | Error e ->
                                            printfn "Receive error: %A" e
                                        | Ok (msg, newTransportState) ->
                                            // Merge transport state: keep server->client state from current ctx,
                                            // update client->server state from receive result
                                            let latestCtx = !ctx
                                            let mergedTransport = {
                                                newTransportState with
                                                    ServerToClientSequence = latestCtx.TransportState.ServerToClientSequence
                                                    ServerToClientIV = latestCtx.TransportState.ServerToClientIV
                                            }
                                            ctx := { latestCtx with TransportState = mergedTransport }

                                            match msg with
                                            | Disconnect(_, desc, _) ->
                                                printfn "Client disconnected: %s" desc
                                                ctx := { !ctx with State = SessionState.Disconnected }

                                            | ChannelOpen(channelType, senderChannel, initialWindowSize, maxPacketSize, data) ->
                                                let currentCtx = !ctx
                                                let! result = Channel.handleChannelOpen
                                                                stream currentCtx.TransportState currentCtx.ChannelManager
                                                                channelType senderChannel initialWindowSize maxPacketSize data
                                                match result with
                                                | Ok (newTransport, newManager, _) ->
                                                    ctx := { !ctx with TransportState = newTransport; ChannelManager = newManager }
                                                | Error e ->
                                                    printfn "Channel open error: %A" e

                                            | ChannelRequest(recipientChannel, requestType, wantReply, data) ->
                                                let currentCtx = !ctx
                                                let! result = Channel.handleChannelRequest
                                                                stream currentCtx.TransportState currentCtx.ChannelManager
                                                                channelCallbacks recipientChannel requestType wantReply data
                                                match result with
                                                | Ok (_, newManager, success, replyChannelOpt) ->
                                                    ctx := { !ctx with ChannelManager = newManager }
                                                    // Send reply with LATEST transport state (after callbacks may have sent data)
                                                    match replyChannelOpt with
                                                    | Some remoteChannel ->
                                                        let latestCtx = !ctx
                                                        let replyMsg = if success then ChannelSuccess(remoteChannel) else ChannelFailure(remoteChannel)
                                                        let! sendResult = Transport.sendMessage stream latestCtx.TransportState replyMsg
                                                        match sendResult with
                                                        | Ok newTransport -> ctx := { !ctx with TransportState = newTransport }
                                                        | Error _ -> ()
                                                    | None -> ()
                                                | Error e ->
                                                    printfn "Channel request error: %A" e

                                            | ChannelData(recipientChannel, data) ->
                                                do! channelCallbacks.OnData recipientChannel data

                                            | ChannelEof(recipientChannel) ->
                                                do! channelCallbacks.OnEof recipientChannel

                                            | ChannelClose(recipientChannel) ->
                                                let currentCtx = !ctx
                                                let! _ = Channel.handleChannelClose
                                                            stream currentCtx.TransportState currentCtx.ChannelManager
                                                            channelCallbacks recipientChannel
                                                do! channelCallbacks.OnClose recipientChannel

                                            | ChannelWindowAdjust(recipientChannel, bytesToAdd) ->
                                                let currentCtx = !ctx
                                                Channel.handleWindowAdjust currentCtx.ChannelManager recipientChannel bytesToAdd |> ignore

                                            | _ ->
                                                ()

                                            return! messageLoop ()
                                    with
                                    | ex ->
                                        printfn "Exception: %s" ex.Message
                            }

                            do! messageLoop ()
                            printfn "Session ended"
        with
        | ex ->
            printfn "Client handler exception: %s" ex.Message
    }

    Async.RunSynchronously(acceptLoop ())

// Run a client that connects and executes a command
let runClient (host: string) (port: int) (username: string) (password: string) (command: string) =
    let config = {
        ClientConfig.defaults with
            Username = username
            HostKeyVerification = AcceptAll
    }
    let authConfig: ClientAuth.ClientAuthConfig = {
        Username = username
        Methods = [ ClientAuth.PasswordAuth password ]
    }

    async {
        printfn "Connecting to %s:%d..." host port
        let! result = Client.connectAsync host port config authConfig
        match result with
        | Error e ->
            printfn "Connection failed: %A" e
        | Ok client ->
            printfn "Connected and authenticated"
            let! execResult = Client.exec client command
            match execResult with
            | Error e ->
                printfn "Exec failed: %A" e
            | Ok (exitCode, stdout, stderr) ->
                let stdoutStr = Encoding.UTF8.GetString(stdout)
                let stderrStr = Encoding.UTF8.GetString(stderr)
                if stdoutStr.Length > 0 then
                    printfn "stdout: %s" stdoutStr
                if stderrStr.Length > 0 then
                    eprintfn "stderr: %s" stderrStr
                printfn "exit code: %d" exitCode
            do! Client.disconnect client
    } |> Async.RunSynchronously

[<EntryPoint>]
let main args =
    match args |> Array.toList with
    | "client" :: host :: port :: user :: pass :: command ->
        let cmd = String.concat " " command
        runClient host (int port) user pass cmd
    | _ ->
        printfn "Usage:"
        printfn "  Server: dotnet run"
        printfn "  Client: dotnet run -- client <host> <port> <user> <password> <command...>"
        runServer ()
    0
