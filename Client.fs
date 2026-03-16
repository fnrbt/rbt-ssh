namespace Ssh

open System
open System.Net.Sockets

type ClientContext = {
    TransportState: TransportState
    KexState: KexState
    ChannelManager: Channel.ChannelManager
    State: SessionState
    Username: string
}

type SshClient = {
    TcpClient: TcpClient
    Stream: NetworkStream
    Context: ClientContext ref
}

/// Callbacks for receiving data from the server
type ClientCallbacks = {
    OnStdout: uint32 -> byte[] -> Async<unit>
    OnStderr: uint32 -> byte[] -> Async<unit>
    OnExit: uint32 -> uint32 -> Async<unit>
    OnChannelClose: uint32 -> Async<unit>
}

module Client =

    /// Connect to an SSH server and authenticate
    let connectAsync
        (host: string)
        (port: int)
        (config: ClientConfig)
        (authConfig: ClientAuth.ClientAuthConfig) = async {

        let client = new TcpClient()
        try
            do! client.ConnectAsync(host, port) |> Async.AwaitTask
            let stream = client.GetStream()

            let transportState = TransportState.createClient config.ClientVersion

            // Version exchange (client reads server version first, then sends)
            let! versionResult = Transport.exchangeVersionsAsClient stream config.ClientVersion
            match versionResult with
            | Error e ->
                client.Dispose()
                return Error e
            | Ok serverVersion ->
                let stateWithVersions = {
                    transportState with
                        ServerVersion = serverVersion
                        ClientVersion = Some config.ClientVersion
                }

                // Key exchange
                let! kexResult = ClientKeyExchange.handleKeyExchange stream stateWithVersions config.HostKeyVerification
                match kexResult with
                | Error e ->
                    client.Dispose()
                    return Error e
                | Ok (transportAfterKex, kexState, _) ->
                    match kexState.SessionId with
                    | None ->
                        client.Dispose()
                        return Error (ProtocolError "No session ID after key exchange")
                    | Some sessionId ->
                        // Authenticate
                        let! authResult = ClientAuth.authenticate stream transportAfterKex sessionId authConfig
                        match authResult with
                        | Error e ->
                            client.Dispose()
                            return Error e
                        | Ok transportAfterAuth ->
                            let ctx = {
                                TransportState = transportAfterAuth
                                KexState = kexState
                                ChannelManager = Channel.ChannelManager.create()
                                State = Authenticated
                                Username = authConfig.Username
                            }
                            let sshClient = {
                                TcpClient = client
                                Stream = stream
                                Context = ref ctx
                            }
                            return Ok sshClient
        with ex ->
            client.Dispose()
            return Error (ConnectionError ex.Message)
    }

    /// Open a session channel
    let openChannel (client: SshClient) = async {
        let ctx = !client.Context
        let (newManager, channel) =
            Channel.ChannelManager.allocateChannel
                ctx.ChannelManager "session" 0u 0u 0u

        // Send CHANNEL_OPEN
        let openMsg = ChannelOpen(
            "session",
            channel.LocalChannel,
            Constants.DefaultWindowSize,
            Constants.DefaultMaxPacketSize,
            [||])
        let! sendResult = Transport.sendMessage client.Stream ctx.TransportState openMsg
        match sendResult with
        | Error e -> return Error e
        | Ok stateAfterSend ->
            client.Context := { ctx with TransportState = stateAfterSend; ChannelManager = newManager }

            // Wait for CHANNEL_OPEN_CONFIRMATION (handle interleaved global requests etc.)
            let rec waitForConfirmation () = async {
                let! recvResult = Transport.receiveMessage client.Stream (!client.Context).TransportState
                match recvResult with
                | Error e -> return Error e
                | Ok (msg, stateAfterRecv) ->
                    client.Context := { !client.Context with TransportState = stateAfterRecv }
                    match msg with
                    | ChannelOpenConfirmation(_recipientChannel, senderChannel, windowSize, maxPacketSize, _) ->
                        Channel.ChannelManager.updateChannel newManager channel.LocalChannel (fun ch ->
                            { ch with
                                RemoteChannel = senderChannel
                                RemoteWindowSize = windowSize
                                RemoteMaxPacketSize = maxPacketSize }
                        ) |> ignore
                        return Ok channel.LocalChannel
                    | ChannelOpenFailure(_, reasonCode, description, _) ->
                        return Error (ChannelError $"Channel open rejected ({reasonCode}): {description}")
                    | GlobalRequest(_, wantReply, _) ->
                        if wantReply then
                            let! _ = Transport.sendMessage client.Stream (!client.Context).TransportState RequestFailure
                            ()
                        return! waitForConfirmation ()
                    | _ ->
                        return! waitForConfirmation ()
            }
            return! waitForConfirmation ()
    }

    /// Wait for ChannelSuccess/ChannelFailure, handling any interleaved messages
    /// (data, window adjust, etc. can arrive before the reply)
    let private waitForChannelReply
        (client: SshClient)
        (pendingData: System.Collections.Generic.List<byte>)
        (pendingStderr: System.Collections.Generic.List<byte>) = async {
        let rec loop () = async {
            let! recvResult = Transport.receiveMessage client.Stream (!client.Context).TransportState
            match recvResult with
            | Error e -> return Error e
            | Ok (msg, stateAfterRecv) ->
                client.Context := { !client.Context with TransportState = stateAfterRecv }
                match msg with
                | ChannelSuccess _ -> return Ok ()
                | ChannelFailure _ -> return Error (ChannelError "Channel request rejected")
                | ChannelData(_, data) ->
                    pendingData.AddRange(data)
                    return! loop ()
                | ChannelExtendedData(_, _, data) ->
                    pendingStderr.AddRange(data)
                    return! loop ()
                | ChannelWindowAdjust(recipientChannel, bytesToAdd) ->
                    Channel.handleWindowAdjust (!client.Context).ChannelManager recipientChannel bytesToAdd |> ignore
                    return! loop ()
                | ChannelEof _ | ChannelClose _ | ChannelRequest _ ->
                    // These can arrive if the server's callback already sent everything;
                    // treat as implicit success
                    return Ok ()
                | _ ->
                    return! loop ()
        }
        return! loop ()
    }

    /// Send a channel request and wait for the reply
    let private sendChannelRequest
        (client: SshClient)
        (channelId: uint32)
        (requestType: string)
        (requestData: byte[]) = async {

        let ctx = !client.Context
        match Channel.ChannelManager.getChannel ctx.ChannelManager channelId with
        | None -> return Error (ChannelError "Unknown channel")
        | Some channel ->
            let requestMsg = ChannelRequest(channel.RemoteChannel, requestType, true, requestData)
            let! sendResult = Transport.sendMessage client.Stream ctx.TransportState requestMsg
            match sendResult with
            | Error e -> return Error e
            | Ok stateAfterSend ->
                client.Context := { !client.Context with TransportState = stateAfterSend }
                let pendingData = System.Collections.Generic.List<byte>()
                let pendingStderr = System.Collections.Generic.List<byte>()
                let! result = waitForChannelReply client pendingData pendingStderr
                return result
    }

    /// Request a PTY on a channel
    let requestPty
        (client: SshClient)
        (channelId: uint32)
        (term: string)
        (widthCols: uint32)
        (heightRows: uint32) = async {
        let requestData = Packet.buildChannelRequestData (
            PtyReq(term, widthCols, heightRows, 0u, 0u, [||]))
        return! sendChannelRequest client channelId "pty-req" requestData
    }

    /// Request shell on a channel
    let requestShell (client: SshClient) (channelId: uint32) = async {
        return! sendChannelRequest client channelId "shell" [||]
    }

    /// Request exec on a channel
    let requestExec (client: SshClient) (channelId: uint32) (command: string) = async {
        let requestData = Packet.buildChannelRequestData (Exec(command))
        return! sendChannelRequest client channelId "exec" requestData
    }

    /// Send data on a channel
    let sendData (client: SshClient) (channelId: uint32) (data: byte[]) = async {
        let ctx = !client.Context
        let! result = Channel.sendChannelData client.Stream ctx.TransportState ctx.ChannelManager channelId data
        match result with
        | Error e -> return Error e
        | Ok newTransport ->
            client.Context := { !client.Context with TransportState = newTransport }
            return Ok ()
    }

    /// Send EOF on a channel
    let sendEof (client: SshClient) (channelId: uint32) = async {
        let ctx = !client.Context
        let! result = Channel.sendChannelEof client.Stream ctx.TransportState ctx.ChannelManager channelId
        match result with
        | Error e -> return Error e
        | Ok newTransport ->
            client.Context := { !client.Context with TransportState = newTransport }
            return Ok ()
    }

    /// Process one incoming message, dispatching to callbacks
    let receiveOne (client: SshClient) (callbacks: ClientCallbacks) = async {
        let ctx = !client.Context
        let! result = Transport.receiveMessage client.Stream ctx.TransportState
        match result with
        | Error e -> return Error e
        | Ok (msg, newTransportState) ->
            client.Context := { !client.Context with TransportState = newTransportState }

            match msg with
            | ChannelData(recipientChannel, data) ->
                do! callbacks.OnStdout recipientChannel data
                return Ok true

            | ChannelExtendedData(recipientChannel, _dataTypeCode, data) ->
                do! callbacks.OnStderr recipientChannel data
                return Ok true

            | ChannelRequest(_, "exit-status", _, data) ->
                let exitStatus = Packet.readUint32 data 0
                // We don't know the channel from the request alone, use 0 as placeholder
                do! callbacks.OnExit 0u exitStatus
                return Ok true

            | ChannelEof _ ->
                return Ok true

            | ChannelClose(recipientChannel) ->
                // Send close back
                match Channel.ChannelManager.getChannel (!client.Context).ChannelManager recipientChannel with
                | Some channel ->
                    let! _ = Transport.sendMessage client.Stream (!client.Context).TransportState (ChannelClose(channel.RemoteChannel))
                    ()
                | None -> ()
                do! callbacks.OnChannelClose recipientChannel
                return Ok false  // Channel closed, done

            | ChannelWindowAdjust(recipientChannel, bytesToAdd) ->
                Channel.handleWindowAdjust (!client.Context).ChannelManager recipientChannel bytesToAdd |> ignore
                return Ok true

            | Disconnect(_, description, _) ->
                client.Context := { !client.Context with State = SessionState.Disconnected }
                return Error (ConnectionError $"Server disconnected: {description}")

            | _ ->
                return Ok true
    }

    /// Run receive loop until channel closes or error
    let receiveLoop (client: SshClient) (callbacks: ClientCallbacks) = async {
        let mutable running = true
        let mutable lastError = None
        while running do
            let! result = receiveOne client callbacks
            match result with
            | Ok true -> ()
            | Ok false -> running <- false
            | Error e ->
                lastError <- Some e
                running <- false
        return
            match lastError with
            | Some e -> Error e
            | None -> Ok ()
    }

    /// Execute a command and collect all output
    let exec (client: SshClient) (command: string) = async {
        let! channelResult = openChannel client
        match channelResult with
        | Error e -> return Error e
        | Ok channelId ->
            let ctx = !client.Context
            match Channel.ChannelManager.getChannel ctx.ChannelManager channelId with
            | None -> return Error (ChannelError "Unknown channel")
            | Some channel ->
                // Send exec request (wantReply=false to avoid ordering issues)
                let requestData = Packet.buildChannelRequestData (Exec(command))
                let requestMsg = ChannelRequest(channel.RemoteChannel, "exec", false, requestData)
                let! sendResult = Transport.sendMessage client.Stream ctx.TransportState requestMsg
                match sendResult with
                | Error e -> return Error e
                | Ok stateAfterSend ->
                    client.Context := { !client.Context with TransportState = stateAfterSend }

                    // Collect all output in a single receive loop
                    let stdout = System.Collections.Generic.List<byte>()
                    let stderr = System.Collections.Generic.List<byte>()
                    let mutable exitCode = 0u

                    let callbacks = {
                        OnStdout = fun _ data -> async { stdout.AddRange(data) }
                        OnStderr = fun _ data -> async { stderr.AddRange(data) }
                        OnExit = fun _ code -> async { exitCode <- code }
                        OnChannelClose = fun _ -> async { () }
                    }

                    let! _ = receiveLoop client callbacks
                    return Ok (exitCode, stdout.ToArray(), stderr.ToArray())
    }

    /// Disconnect gracefully
    let disconnect (client: SshClient) = async {
        let ctx = !client.Context
        let disconnectMsg = Disconnect(
            DisconnectReason.SSH_DISCONNECT_BY_APPLICATION,
            "Client disconnecting", "")
        let! _ = Transport.sendMessage client.Stream ctx.TransportState disconnectMsg
        client.Context := { !client.Context with State = SessionState.Disconnected }
        client.TcpClient.Dispose()
    }
