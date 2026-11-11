module Program

open System
open System.Text
open System.Net.Sockets
open System.Collections.Concurrent
open System.Threading
open Rbt.Ssh

let rot13 (s: string) =
    s |> String.map (fun c ->
        match c with
        | c when c >= 'a' && c <= 'z' -> char ((int c - int 'a' + 13) % 26 + int 'a')
        | c when c >= 'A' && c <= 'Z' -> char ((int c - int 'A' + 13) % 26 + int 'A')
        | _ -> c)

// Each connection has its own channel namespace and serialized transport.
let runServer () =
    let hostKey = Crypto.createEd25519HostKey()
    let config = { ServerConfig.defaults with ListenPort = 2222; HostKeys = [ hostKey ] }
    let auth = {
        ValidatePassword = fun _ _ -> async { return Accepted }
        ValidatePublicKey = fun _ _ _ -> async { return Rejected }
    }
    let listener = new TcpListener(System.Net.IPAddress.Any, config.ListenPort)
    listener.Start()
    printfn "SSH Rot13 Server listening on port %d" config.ListenPort
    printfn "Host key fingerprint: %s" (PrivateKeyFile.fingerprint hostKey.PublicKeyBlob)
    let handleClient (client: TcpClient) = async {
        use client = client
        use stream = client.GetStream()
        use sessionCts = new CancellationTokenSource()
        let factory stream ctx locks _ =
            // Queued input is bounded by the SSH receive window. The worker
            // returns credit only after it has processed each chunk, so it can
            // wait for outbound credit without blocking WINDOW_ADJUST handling.
            let shells = ConcurrentDictionary<uint32, System.Threading.Channels.Channel<byte[]>>()
            sessionCts.Token.Register(fun () ->
                for input in shells.Values do input.Writer.TryComplete() |> ignore) |> ignore
            let send id (text: string) = async {
                match! Session.sendDataRef stream ctx locks id (Encoding.UTF8.GetBytes text) sessionCts.Token with
                | Ok () -> ()
                | Error error -> failwithf "Shell send failed: %A" error
            }
            let close id = async {
                let! _ = Session.closeChannelWithStatusRef stream ctx locks id 0u
                return ()
            }
            let startShell id =
                let input = System.Threading.Channels.Channel.CreateUnbounded<byte[]>()
                shells.[id] <- input
                let manager = (!ctx).ChannelManager
                lock manager.Sync (fun () -> manager.DeferredInput.Add(id) |> ignore)
                let run = async {
                    let buffer = StringBuilder()
                    let mutable running = true
                    let prompt () = send id "rot13> "
                    let processLine (line: string) = async {
                        let trimmed = line.TrimEnd([| '\r'; '\n' |])
                        if trimmed = "exit" || trimmed = "quit" then
                            do! send id "Goodbye!\r\n"
                            do! close id
                            running <- false
                        else
                            do! send id (rot13 trimmed + "\r\n")
                            do! prompt ()
                    }
                    try
                        do! send id "Welcome to the Rot13 Shell!\r\n"
                        do! send id "Type text and press Enter to see it rot13'd.\r\n"
                        do! send id "Type 'exit' or 'quit' to disconnect.\r\n"
                        do! send id "\r\n"
                        do! prompt ()
                        while running do
                            let! available = input.Reader.WaitToReadAsync(sessionCts.Token).AsTask() |> Async.AwaitTask
                            if not available then running <- false
                            else
                                let mutable data = Unchecked.defaultof<byte[]>
                                if input.Reader.TryRead(&data) then
                                    let text = Encoding.UTF8.GetString(data)
                                    do! send id text
                                    for c in text do
                                        if not running then ()
                                        elif c = '\r' || c = '\n' then
                                            let line = buffer.ToString()
                                            buffer.Clear() |> ignore
                                            if line.Length > 0 then
                                                do! send id "\r\n"
                                                do! processLine line
                                        elif c = '\x7f' || c = '\b' then
                                            if buffer.Length > 0 then
                                                buffer.Remove(buffer.Length - 1, 1) |> ignore
                                                do! send id "\b \b"
                                        elif c = '\x03' then
                                            do! send id "^C\r\n"
                                            do! prompt ()
                                            buffer.Clear() |> ignore
                                        elif c >= ' ' then
                                            buffer.Append(c) |> ignore
                                    if running then
                                        match! Session.replenishInputRef stream ctx locks id (uint32 data.Length) with
                                        | Ok () -> ()
                                        | Error _ -> running <- false
                    with
                    | :? OperationCanceledException -> ()
                    | ex -> printfn "Shell error: %s" ex.Message
                }
                Async.Start(async {
                    try
                        do! run
                    finally
                        input.Writer.TryComplete() |> ignore
                        shells.TryRemove(id) |> ignore
                }, sessionCts.Token)
            {
                OnData = fun id data -> async {
                    match shells.TryGetValue id with
                    | true, input when data.Length > 0 -> input.Writer.TryWrite(data) |> ignore
                    | _ -> ()
                }
                OnExtendedData = fun _ _ _ -> async { () }
                OnEof = fun id -> async {
                    match shells.TryGetValue id with
                    | true, input -> input.Writer.TryComplete() |> ignore
                    | _ -> ()
                }
                OnClose = fun id -> async {
                    match shells.TryRemove id with
                    | true, input -> input.Writer.TryComplete() |> ignore
                    | _ -> ()
                }
                OnPtyRequest = fun _ _ _ _ -> async { return true }
                OnShellRequest = fun id -> async {
                    startShell id
                    return true
                }
                OnExecRequest = fun id command -> async {
                    // Do not wait for remote output credit on the message loop.
                    Async.Start(async {
                        try
                            do! send id (rot13 command + "\n")
                            do! close id
                        with
                        | :? OperationCanceledException -> ()
                        | ex -> printfn "Exec error: %s" ex.Message
                    }, sessionCts.Token)
                    return true
                }
            }
        try
            let! result = Session.runSessionWithFactory stream config auth factory
            match result with
            | Error error -> printfn "Session error: %A" error
            | Ok _ -> ()
        finally
            sessionCts.Cancel()
    }
    let rec accept () = async {
        let! client = listener.AcceptTcpClientAsync() |> Async.AwaitTask
        Async.Start(handleClient client)
        return! accept ()
    }
    Async.RunSynchronously(accept ())


// Run a client that connects and executes a command
let runClient (host: string) (port: int) (username: string) (password: string) (fingerprint: string) (command: string) =
    let config = {
        ClientConfig.defaults with
            Username = username
            HostKeyVerification = Fingerprint [ fingerprint ]
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
    | "client" :: host :: port :: user :: pass :: fingerprint :: command when not command.IsEmpty ->
        let cmd = String.concat " " command
        runClient host (int port) user pass fingerprint cmd
    | [] -> runServer ()
    | _ ->
        printfn "Usage:"
        printfn "  Server: dotnet run"
        printfn "  Client: dotnet run -- client <host> <port> <user> <password> <host-fingerprint> <command...>"
    0
