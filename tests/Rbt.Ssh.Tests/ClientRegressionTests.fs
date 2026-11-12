module Rbt.Ssh.Tests.ClientRegressionTests

open System
open System.Net
open System.Net.Sockets
open System.Text
open Xunit
open Rbt.Ssh

let private run work = Async.RunSynchronously(work, timeout = 5000)

let private pair () = async {
    let listener = new TcpListener(IPAddress.Loopback, 0)
    listener.Start()
    try
        let port = (listener.LocalEndpoint :?> IPEndPoint).Port
        let accepting = listener.AcceptTcpClientAsync()
        let clientSocket = new TcpClient()
        do! clientSocket.ConnectAsync(IPAddress.Loopback, port) |> Async.AwaitTask
        let! serverSocket = accepting |> Async.AwaitTask
        let manager, _ =
            Channel.ChannelManager.allocateChannel (Channel.ChannelManager.create())
                "session" 7u Constants.DefaultWindowSize Constants.DefaultMaxPacketSize
        let client = {
            TcpClient = clientSocket
            Stream = clientSocket.GetStream()
            Context = ref {
                TransportState = TransportState.createClient "SSH-2.0-regression"
                KexState = KexState.empty
                ChannelManager = manager
                State = Authenticated
                Username = "regression"
            }
            Runtime = ClientRuntime.create()
        }
        return client, serverSocket
    finally
        listener.Stop()
}

let private serverSend (stream: NetworkStream) (state: TransportState ref) msg = async {
    match! Transport.sendMessage stream !state msg with
    | Ok next -> state := Transport.adoptWriteCursors !state next
    | Error e -> failwithf "Server send failed: %A" e
}

let private serverRead (stream: NetworkStream) (state: TransportState ref) = async {
    match! Transport.receiveMessage stream !state with
    | Ok (msg, next) ->
        state := Transport.adoptReadCursors !state next
        return msg
    | Error e -> return failwithf "Server receive failed: %A" e
}

let private callbacks (stdout: ResizeArray<uint32 * string>)
    (stderr: ResizeArray<uint32 * string>) (exits: ResizeArray<uint32 * uint32>)
    (closes: ResizeArray<uint32>) : ClientCallbacks = {
    OnStdout = fun channel data -> async { stdout.Add(channel, Encoding.UTF8.GetString data) }
    OnStderr = fun channel data -> async { stderr.Add(channel, Encoding.UTF8.GetString data) }
    OnExit = fun channel code -> async { exits.Add(channel, code) }
    OnChannelClose = fun channel -> async { closes.Add(channel) }
}

[<Fact>]
let ``parallel writers and inbound reader retain both directional sequence numbers`` () =
    run (async {
        let! client, serverSocket = pair ()
        use serverSocket = serverSocket
        try
            let stream = serverSocket.GetStream()
            let serverState = ref (TransportState.create "SSH-2.0-regression")
            let count = 40
            let server = async {
                let writer = async {
                    for i in 1 .. count do
                        do! serverSend stream serverState (Ignore [| byte i |])
                }
                let reader = async {
                    for _ in 1 .. count do
                        match! serverRead stream serverState with
                        | ChannelData(7u, bytes) -> Assert.Single(bytes) |> ignore
                        | other -> failwithf "Unexpected client message: %A" other
                }
                // Separate directional state is maintained independently by
                // the scripted peer as well as the library client.
                do! Async.Parallel [ writer; reader ] |> Async.Ignore
            }
            let clientWork = async {
                let writer = async {
                    for i in 1 .. count do
                        match! Client.sendData client 0u [| byte i |] with
                        | Ok () -> ()
                        | Error e -> failwithf "Client send failed: %A" e
                }
                let reader = async {
                    let stdout = ResizeArray<uint32 * string>()
                    let stderr = ResizeArray<uint32 * string>()
                    let exits = ResizeArray<uint32 * uint32>()
                    let closes = ResizeArray<uint32>()
                    for _ in 1 .. count do
                        match! Client.receiveOne client (callbacks stdout stderr exits closes) with
                        | Ok true -> ()
                        | other -> failwithf "Client receive failed: %A" other
                }
                do! Async.Parallel [ writer; reader ] |> Async.Ignore
            }
            do! Async.Parallel [ server; clientWork ] |> Async.Ignore
            let state = (!client.Context).TransportState
            Assert.Equal(uint32 count, state.ClientToServerSequence)
            Assert.Equal(uint32 count, state.ServerToClientSequence)
        finally
            client.TcpClient.Dispose()
    })

[<Fact>]
let ``request reply retains early output control and unrelated replies exactly once`` () =
    run (async {
        let! client, serverSocket = pair ()
        use serverSocket = serverSocket
        try
            let stream = serverSocket.GetStream()
            let state = ref (TransportState.create "SSH-2.0-regression")
            let stdout = ResizeArray<uint32 * string>()
            let stderr = ResizeArray<uint32 * string>()
            let exits = ResizeArray<uint32 * uint32>()
            let closes = ResizeArray<uint32>()
            let receiveCallbacks = callbacks stdout stderr exits closes
            let server = async {
                match! serverRead stream state with
                | ChannelRequest(7u, "exec", true, _) -> ()
                | other -> failwithf "Unexpected request: %A" other
                do! serverSend stream state (ChannelData(0u, Encoding.UTF8.GetBytes "early"))
                do! serverSend stream state (ChannelExtendedData(0u, 1u, Encoding.UTF8.GetBytes "warning"))
                do! serverSend stream state (ChannelRequest(0u, "exit-status", false, Packet.writeUint32 9u))
                do! serverSend stream state (ChannelEof 0u)
                do! serverSend stream state (ChannelSuccess 1u)
                do! serverSend stream state (ChannelSuccess 0u)
                // Two window replenishments are required when replaying the data.
                for _ in 1 .. 2 do
                    match! serverRead stream state with
                    | ChannelWindowAdjust(7u, _) -> ()
                    | other -> failwithf "Unexpected response: %A" other
            }
            let clientWork = async {
                match! Client.requestExec client 0u "true" with
                | Ok () -> ()
                | Error e -> failwithf "Request failed: %A" e
                for _ in 1 .. 5 do
                    match! Client.receiveOne client receiveCallbacks with
                    | Ok true -> ()
                    | other -> failwithf "Replay failed: %A" other
            }
            do! Async.Parallel [ server; clientWork ] |> Async.Ignore
            Assert.Equal<(uint32 * string) list>([ 0u, "early" ], List.ofSeq stdout)
            Assert.Equal<(uint32 * string) list>([ 0u, "warning" ], List.ofSeq stderr)
            Assert.Equal<(uint32 * uint32) list>([ 0u, 9u ], List.ofSeq exits)
            Assert.Empty(closes)
        finally
            client.TcpClient.Dispose()
    })

[<Fact>]
let ``channel close before reply fails request and releases credit waiters`` () =
    run (async {
        let! client, serverSocket = pair ()
        use serverSocket = serverSocket
        try
            Channel.ChannelManager.updateChannel (!client.Context).ChannelManager 0u
                (fun channel -> { channel with RemoteWindowSize = 0u }) |> ignore
            let stream = serverSocket.GetStream()
            let state = ref (TransportState.create "SSH-2.0-regression")
            let server = async {
                match! serverRead stream state with
                | ChannelRequest(7u, "shell", true, _) -> ()
                | other -> failwithf "Unexpected request: %A" other
                do! serverSend stream state (ChannelClose 0u)
                match! serverRead stream state with
                | ChannelClose 7u -> ()
                | other -> failwithf "Expected close acknowledgement: %A" other
            }
            let clientWork = async {
                let waiting = Client.sendData client 0u [| 42uy |] |> Async.StartAsTask
                match! Client.requestShell client 0u with
                | Error (ChannelError _) -> ()
                | other -> failwithf "Close was incorrectly accepted: %A" other
                let! sendResult = waiting |> Async.AwaitTask
                match sendResult with
                | Error (ChannelError _) -> ()
                | other -> failwithf "Credit wait was not released: %A" other
                let stdout = ResizeArray<uint32 * string>()
                let stderr = ResizeArray<uint32 * string>()
                let exits = ResizeArray<uint32 * uint32>()
                let closes = ResizeArray<uint32>()
                match! Client.receiveOne client (callbacks stdout stderr exits closes) with
                | Ok false -> Assert.Equal<uint32 list>([ 0u ], List.ofSeq closes)
                | other -> failwithf "Close not replayed: %A" other
            }
            do! Async.Parallel [ server; clientWork ] |> Async.Ignore
            Assert.True(Channel.ChannelManager.getChannel (!client.Context).ChannelManager 0u |> Option.isNone)
        finally
            client.TcpClient.Dispose()
    })

[<Fact>]
let ``disconnect releases a sender waiting for window credit`` () =
    run (async {
        let! client, serverSocket = pair ()
        use serverSocket = serverSocket
        try
            Channel.ChannelManager.updateChannel (!client.Context).ChannelManager 0u
                (fun channel -> { channel with RemoteWindowSize = 0u }) |> ignore
            let waiting = Client.sendData client 0u [| 42uy |] |> Async.StartAsTask
            do! Client.disconnect client
            let! result = waiting |> Async.AwaitTask
            match result with
            | Error _ -> ()
            | Ok () -> failwith "A closed connection completed a blocked send"
            Assert.True(Channel.ChannelManager.getChannel (!client.Context).ChannelManager 0u |> Option.isNone)
        finally
            client.TcpClient.Dispose()
    })

[<Fact>]
let ``exit status callback identifies its actual local channel`` () =
    run (async {
        let! client, serverSocket = pair ()
        use serverSocket = serverSocket
        try
            let stream = serverSocket.GetStream()
            let state = ref (TransportState.create "SSH-2.0-regression")
            let manager, _ = Channel.ChannelManager.allocateChannel (!client.Context).ChannelManager
                                    "session" 8u Constants.DefaultWindowSize Constants.DefaultMaxPacketSize
            client.Context := { !client.Context with ChannelManager = manager }
            do! serverSend stream state (ChannelRequest(1u, "exit-status", false, Packet.writeUint32 3u))
            let stdout = ResizeArray<uint32 * string>()
            let stderr = ResizeArray<uint32 * string>()
            let exits = ResizeArray<uint32 * uint32>()
            let closes = ResizeArray<uint32>()
            match! Client.receiveOne client (callbacks stdout stderr exits closes) with
            | Ok true -> Assert.Equal<(uint32 * uint32) list>([ 1u, 3u ], List.ofSeq exits)
            | other -> failwithf "Exit status not delivered: %A" other
        finally
            client.TcpClient.Dispose()
    })

[<Fact>]
let ``exec rejects close without exit status and propagates transport errors`` () =
    let exercise disconnect = async {
        let! client, serverSocket = pair ()
        use serverSocket = serverSocket
        try
            let stream = serverSocket.GetStream()
            let state = ref (TransportState.create "SSH-2.0-regression")
            let server = async {
                match! serverRead stream state with
                | ChannelOpen("session", 1u, _, _, _) -> ()
                | other -> failwithf "Unexpected open: %A" other
                do! serverSend stream state (ChannelOpenConfirmation(1u, 12u,
                                         Constants.DefaultWindowSize, Constants.DefaultMaxPacketSize, [||]))
                match! serverRead stream state with
                | ChannelRequest(12u, "exec", false, _) -> ()
                | other -> failwithf "Unexpected exec: %A" other
                if disconnect then serverSocket.Dispose()
                else
                    do! serverSend stream state (ChannelClose 1u)
                    match! serverRead stream state with
                    | ChannelClose 12u -> ()
                    | other -> failwithf "Unexpected close response: %A" other
            }
            let clientWork = async {
                match! Client.exec client "true" with
                | Error (ChannelError _) when not disconnect -> ()
                | Error (ConnectionError _) when disconnect -> ()
                | other -> failwithf "Exec masked failure: %A" other
            }
            do! Async.Parallel [ server; clientWork ] |> Async.Ignore
        finally
            client.TcpClient.Dispose()
    }
    run (exercise false)
    run (exercise true)

[<Fact>]
let ``connect timeout includes silent version exchange`` () =
    run (async {
        let listener = new TcpListener(IPAddress.Loopback, 0)
        listener.Start()
        try
            let port = (listener.LocalEndpoint :?> IPEndPoint).Port
            let accepting = listener.AcceptTcpClientAsync()
            let config = { ClientConfig.defaults with ConnectTimeout = TimeSpan.FromMilliseconds 100.0 }
            let auth : ClientAuth.ClientAuthConfig = { Username = "tester"; Methods = [] }
            let! result = Client.connectAsync "127.0.0.1" port config auth
            let! accepted = accepting |> Async.AwaitTask
            use accepted = accepted
            match result with
            | Error (ConnectionError _) -> ()
            | other -> failwithf "Silent server did not time out: %A" other
            let single = Array.zeroCreate<byte> 1
            let! count = accepted.GetStream().ReadAsync(single, 0, 1) |> Async.AwaitTask
            Assert.Equal(0, count)
        finally
            listener.Stop()
    })

[<Fact>]
let ``send larger than the peer window completes when nothing else reads`` () =
    Async.RunSynchronously(async {
        let! client, serverSocket = pair ()
        use serverSocket = serverSocket
        try
            let window = 32768
            Channel.ChannelManager.updateChannel (!client.Context).ChannelManager 0u
                (fun channel -> { channel with RemoteWindowSize = uint32 window }) |> ignore
            let payload = Array.init (4 * 1024 * 1024) (fun i -> byte (i * 31 + i / 4096))
            let stream = serverSocket.GetStream()
            let state = ref (TransportState.create "SSH-2.0-regression")
            let events = [ "first"; "second"; "third" ]
            let server = async {
                let received = ResizeArray<byte>(payload.Length)
                let mutable replenished = 0
                let mutable sentEvents = 0
                let mutable packets = 0
                let eventBytes = events |> List.sumBy (fun e -> e.Length)
                while received.Count < payload.Length || replenished < eventBytes do
                    match! serverRead stream state with
                    | ChannelData(7u, bytes) ->
                        received.AddRange bytes
                        packets <- packets + 1
                        // Interleave output early in the transfer; the sender
                        // must retain it and return its credit.
                        if packets % 5 = 0 && sentEvents < events.Length then
                            do! serverSend stream state (ChannelData(0u, Encoding.UTF8.GetBytes events.[sentEvents]))
                            sentEvents <- sentEvents + 1
                        // Credit is granted only as the peer consumes data.
                        do! serverSend stream state (ChannelWindowAdjust(0u, uint32 bytes.Length))
                    | ChannelWindowAdjust(7u, bytes) -> replenished <- replenished + int bytes
                    | other -> failwithf "Unexpected client message: %A" other
                Assert.Equal(eventBytes, replenished)
                Assert.True((payload = received.ToArray()), "payload arrived out of order or altered")
            }
            let clientWork = async {
                // Write everything before reading anything, as a git push does.
                match! Client.sendData client 0u payload with
                | Ok () -> ()
                | Error e -> failwithf "Client send failed: %A" e
            }
            do! Async.Parallel [ server; clientWork ] |> Async.Ignore
            let stdout = ResizeArray<uint32 * string>()
            let stderr = ResizeArray<uint32 * string>()
            let exits = ResizeArray<uint32 * uint32>()
            let closes = ResizeArray<uint32>()
            for _ in events do
                match! Client.receiveOne client (callbacks stdout stderr exits closes) with
                | Ok true -> ()
                | other -> failwithf "Client receive failed: %A" other
            Assert.Equal<string list>(events, stdout |> Seq.map snd |> List.ofSeq)
        finally
            client.TcpClient.Dispose()
    }, timeout = 30000)
