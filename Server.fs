namespace Rbt.Ssh

open System
open System.Net
open System.Net.Sockets
open System.Threading

type SshServer = {
    Listener: TcpListener
    Config: ServerConfig
    AuthCallbacks: AuthCallbacks
    ChannelCallbacks: ChannelCallbacks
    CancellationTokenSource: CancellationTokenSource
}

module Server =

    // Create default channel callbacks (echo server behavior)
    let defaultChannelCallbacks () =
        let mutable dataHandler: (uint32 -> byte[] -> Async<unit>) option = None
        let mutable shellHandler: (uint32 -> Async<bool>) option = None
        let mutable execHandler: (uint32 -> string -> Async<bool>) option = None

        {
            OnData = fun channelId data -> async {
                match dataHandler with
                | Some handler -> do! handler channelId data
                | None -> ()
            }
            OnExtendedData = fun _channelId _dataType _data -> async { () }
            OnEof = fun _channelId -> async { () }
            OnClose = fun _channelId -> async { () }
            OnPtyRequest = fun _channelId _term _width _height -> async { return true }
            OnShellRequest = fun channelId -> async {
                match shellHandler with
                | Some handler -> return! handler channelId
                | None -> return true
            }
            OnExecRequest = fun channelId command -> async {
                match execHandler with
                | Some handler -> return! handler channelId command
                | None -> return true
            }
        }

    // Create default auth callbacks (accepts any password)
    let defaultAuthCallbacks () =
        {
            ValidatePassword = fun _user _password -> async { return Rejected }
            ValidatePublicKey = fun _user _algorithm _publicKey -> async { return Rejected }
        }

    // Create a new SSH server
    let create (config: ServerConfig) (authCallbacks: AuthCallbacks) (channelCallbacks: ChannelCallbacks) =
        let listener = new TcpListener(IPAddress.Any, config.ListenPort)
        {
            Listener = listener
            Config = config
            AuthCallbacks = authCallbacks
            ChannelCallbacks = channelCallbacks
            CancellationTokenSource = new CancellationTokenSource()
        }

    // Handle a single client connection
    let handleClient
        (client: TcpClient)
        (config: ServerConfig)
        (authCallbacks: AuthCallbacks)
        (channelCallbacks: ChannelCallbacks) = async {

        use client = client
        use stream = client.GetStream()

        try
            let! result = Session.runSession stream config authCallbacks channelCallbacks
            match result with
            | Ok ctx ->
                printfn "Session completed for user: %s" (ctx.Username |> Option.defaultValue "unknown")
            | Error e ->
                printfn "Session error: %A" e
        with ex ->
            printfn "Exception in client handler: %s" ex.Message
    }

    // Start accepting connections
    let startAsync (server: SshServer) = async {
        server.Listener.Start()
        printfn "SSH server listening on port %d" server.Config.ListenPort

        let token = server.CancellationTokenSource.Token

        while not token.IsCancellationRequested do
            try
                let! client = server.Listener.AcceptTcpClientAsync() |> Async.AwaitTask
                printfn "New connection from %s" (client.Client.RemoteEndPoint.ToString())

                // Handle client in background
                Async.Start(
                    handleClient client server.Config server.AuthCallbacks server.ChannelCallbacks,
                    token
                )
            with
            | :? ObjectDisposedException -> ()
            | ex when token.IsCancellationRequested -> ()
            | ex -> printfn "Accept error: %s" ex.Message
    }

    // Start the server (blocking)
    let start (server: SshServer) =
        Async.RunSynchronously(startAsync server)

    // Stop the server
    let stop (server: SshServer) =
        server.CancellationTokenSource.Cancel()
        server.Listener.Stop()

    // Create a simple echo server for testing
    let createEchoServer (port: int) (hostKey: HostKey) (validatePassword: string -> string -> bool) =
        let config = {
            ServerConfig.defaults with
                ListenPort = port
                HostKeys = [ hostKey ]
        }

        // Track active sessions for echo behavior
        let activeSessions = System.Collections.Concurrent.ConcurrentDictionary<uint32, NetworkStream * SessionContext ref>()

        let authCallbacks = {
            ValidatePassword = fun user password -> async {
                if validatePassword user password then
                    return Accepted
                else
                    return Rejected
            }
            ValidatePublicKey = fun _user _algorithm _publicKey -> async {
                return Rejected
            }
        }

        let channelCallbacks = {
            OnData = fun channelId data -> async {
                // Echo data back (this is a simplified example)
                printfn "Received %d bytes on channel %d" data.Length channelId
            }
            OnExtendedData = fun _channelId _dataType _data -> async { () }
            OnEof = fun channelId -> async {
                printfn "EOF on channel %d" channelId
            }
            OnClose = fun channelId -> async {
                printfn "Channel %d closed" channelId
            }
            OnPtyRequest = fun _channelId term _width _height -> async {
                printfn "PTY request: %s" term
                return true
            }
            OnShellRequest = fun channelId -> async {
                printfn "Shell request on channel %d" channelId
                return true
            }
            OnExecRequest = fun channelId command -> async {
                printfn "Exec request on channel %d: %s" channelId command
                return true
            }
        }

        create config authCallbacks channelCallbacks

    // Create server with custom handlers
    type ServerBuilder = {
        mutable Config: ServerConfig
        mutable PasswordValidator: (string -> string -> Async<AuthResult>) option
        mutable PublicKeyValidator: (string -> string -> byte[] -> Async<AuthResult>) option
        mutable OnData: (uint32 -> byte[] -> Async<unit>) option
        mutable OnShell: (uint32 -> Async<bool>) option
        mutable OnExec: (uint32 -> string -> Async<bool>) option
        mutable OnPty: (uint32 -> string -> uint32 -> uint32 -> Async<bool>) option
        mutable OnEof: (uint32 -> Async<unit>) option
        mutable OnClose: (uint32 -> Async<unit>) option
    }

    let builder () = {
        Config = ServerConfig.defaults
        PasswordValidator = None
        PublicKeyValidator = None
        OnData = None
        OnShell = None
        OnExec = None
        OnPty = None
        OnEof = None
        OnClose = None
    }

    let withPort (port: int) (b: ServerBuilder) =
        b.Config <- { b.Config with ListenPort = port }
        b

    let withHostKey (hostKey: HostKey) (b: ServerBuilder) =
        b.Config <- { b.Config with HostKeys = hostKey :: b.Config.HostKeys }
        b

    let withPasswordAuth (validator: string -> string -> Async<AuthResult>) (b: ServerBuilder) =
        b.PasswordValidator <- Some validator
        b

    let withPublicKeyAuth (validator: string -> string -> byte[] -> Async<AuthResult>) (b: ServerBuilder) =
        b.PublicKeyValidator <- Some validator
        b

    let withDataHandler (handler: uint32 -> byte[] -> Async<unit>) (b: ServerBuilder) =
        b.OnData <- Some handler
        b

    let withShellHandler (handler: uint32 -> Async<bool>) (b: ServerBuilder) =
        b.OnShell <- Some handler
        b

    let withExecHandler (handler: uint32 -> string -> Async<bool>) (b: ServerBuilder) =
        b.OnExec <- Some handler
        b

    let withPtyHandler (handler: uint32 -> string -> uint32 -> uint32 -> Async<bool>) (b: ServerBuilder) =
        b.OnPty <- Some handler
        b

    let withEofHandler (handler: uint32 -> Async<unit>) (b: ServerBuilder) =
        b.OnEof <- Some handler
        b

    let withCloseHandler (handler: uint32 -> Async<unit>) (b: ServerBuilder) =
        b.OnClose <- Some handler
        b

    let build (b: ServerBuilder) =
        let authCallbacks = {
            ValidatePassword =
                match b.PasswordValidator with
                | Some v -> v
                | None -> fun _ _ -> async { return Rejected }
            ValidatePublicKey =
                match b.PublicKeyValidator with
                | Some v -> v
                | None -> fun _ _ _ -> async { return Rejected }
        }

        let channelCallbacks = {
            OnData =
                match b.OnData with
                | Some h -> h
                | None -> fun _ _ -> async { () }
            OnExtendedData = fun _ _ _ -> async { () }
            OnEof =
                match b.OnEof with
                | Some h -> h
                | None -> fun _ -> async { () }
            OnClose =
                match b.OnClose with
                | Some h -> h
                | None -> fun _ -> async { () }
            OnPtyRequest =
                match b.OnPty with
                | Some h -> h
                | None -> fun _ _ _ _ -> async { return true }
            OnShellRequest =
                match b.OnShell with
                | Some h -> h
                | None -> fun _ -> async { return true }
            OnExecRequest =
                match b.OnExec with
                | Some h -> h
                | None -> fun _ _ -> async { return true }
        }

        create b.Config authCallbacks channelCallbacks

// Example usage module
module Example =
    open Server

    let runSimpleServer () =
        // Generate a host key
        let hostKey = Crypto.createEd25519HostKey()

        // Create server with builder pattern
        let server =
            builder()
            |> withPort 2222
            |> withHostKey hostKey
            |> withPasswordAuth (fun user password -> async {
                if user = "test" && password = "test" then
                    return Accepted
                else
                    return Rejected
            })
            |> withShellHandler (fun channelId -> async {
                printfn "Shell started on channel %d" channelId
                return true
            })
            |> withDataHandler (fun channelId data -> async {
                let text = System.Text.Encoding.UTF8.GetString(data)
                printfn "Channel %d received: %s" channelId text
            })
            |> build

        printfn "Starting SSH server on port 2222..."
        printfn "Test with: ssh -o StrictHostKeyChecking=no test@localhost -p 2222"
        start server
