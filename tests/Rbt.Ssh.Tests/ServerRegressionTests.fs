module Rbt.Ssh.Tests.ServerRegressionTests

open System
open System.Net
open System.Net.Sockets
open System.Threading
open System.Threading.Tasks
open Xunit
open Rbt.Ssh

let private callbacks = {
    OnData = fun _ _ -> async { () }
    OnExtendedData = fun _ _ _ -> async { () }
    OnEof = fun _ -> async { () }
    OnClose = fun _ -> async { () }
    OnPtyRequest = fun _ _ _ _ -> async { return true }
    OnShellRequest = fun _ -> async { return true }
    OnExecRequest = fun _ _ -> async { return true }
}

let private channel window packet =
    let manager, ch = Channel.ChannelManager.allocateChannel (Channel.ChannelManager.create()) "session" 7u 100u 100u
    Channel.ChannelManager.updateChannel manager ch.LocalChannel (fun c -> { c with LocalWindowSize = window; LocalMaxPacketSize = packet }) |> ignore
    manager, ch.LocalChannel

[<Fact>]
let ``ordinary and extended input share bounded receive credit`` () =
    let manager, id = channel 5u 4u
    Assert.True(Channel.handleChannelData manager callbacks id [| 1uy; 2uy; 3uy |] |> Async.RunSynchronously |> Result.isOk)
    Assert.True(Channel.handleChannelExtendedData manager callbacks id 1u [| 4uy; 5uy |] |> Async.RunSynchronously |> Result.isOk)
    Assert.Equal(0u, (Channel.ChannelManager.getChannel manager id).Value.LocalWindowSize)
    Assert.True(Channel.handleChannelExtendedData manager callbacks id 1u [| 6uy |] |> Async.RunSynchronously |> Result.isError)
    Assert.Equal(0u, (Channel.ChannelManager.getChannel manager id).Value.LocalWindowSize)
    let manager2, id2 = channel 10u 4u
    Assert.True(Channel.handleChannelData manager2 callbacks id2 (Array.zeroCreate 5) |> Async.RunSynchronously |> Result.isError)
    Assert.True(Channel.handleChannelExtendedData manager2 callbacks id2 1u (Array.zeroCreate 5) |> Async.RunSynchronously |> Result.isError)
    Assert.Equal(10u, (Channel.ChannelManager.getChannel manager2 id2).Value.LocalWindowSize)

[<Fact>]
let ``only one successful shell or exec starts per channel`` () =
    let manager, id = channel 100u 100u
    let mutable starts = 0
    let handlers = {
        callbacks with
            OnExecRequest = fun _ _ -> async { starts <- starts + 1; return true }
            OnShellRequest = fun _ -> async { starts <- starts + 1; return true }
    }
    let call request data =
        Channel.handleChannelRequest Unchecked.defaultof<NetworkStream> (TransportState.create "SSH-2.0-test") manager handlers id request true data
        |> Async.RunSynchronously
    let data = Packet.buildChannelRequestData (Exec "run")
    match call "exec" [| 0uy; 0uy; 0uy; 3uy; 65uy |] with
    | Error (ProtocolError _) -> ()
    | result -> failwithf "malformed command was not rejected: %A" result
    Assert.Equal(0, starts)
    match call "exec" data, call "shell" [||], call "exec" data with
    | Ok (_, _, true, _), Ok (_, _, false, _), Ok (_, _, false, _) -> ()
    | results -> failwithf "unexpected replies: %A" results
    Assert.Equal(1, starts)

[<Fact>]
let ``credit wait completes on either adjustment or cancellation`` () =
    let manager, id = channel 10u 10u
    Channel.ChannelManager.updateChannel manager id (fun ch -> { ch with RemoteWindowSize = 0u }) |> ignore
    let signal = match Channel.acquireOutboundCredit manager id [| 1uy |] 0 with Ok (Channel.Waiting signal) -> signal | _ -> failwith "expected wait"
    let waiting = Channel.waitForCredit signal CancellationToken.None |> Async.StartAsTask
    Channel.handleWindowAdjust manager id 1u |> ignore
    Assert.True(waiting.Wait(TimeSpan.FromSeconds 2.0))
    Assert.True(Result.isOk waiting.Result)
    let pending = TaskCompletionSource<unit>(TaskCreationOptions.RunContinuationsAsynchronously)
    use cts = new CancellationTokenSource()
    let cancelled = Channel.waitForCredit pending cts.Token |> Async.StartAsTask
    cts.Cancel()
    Assert.True(cancelled.Wait(TimeSpan.FromSeconds 2.0))
    Assert.True(Result.isError cancelled.Result)

let private server config onExec =
    let listener = new TcpListener(IPAddress.Loopback, 0)
    listener.Start()
    let port = (listener.LocalEndpoint :?> IPEndPoint).Port
    let callbacks: ExecServerCallbacks = {
        ValidatePassword = fun _ _ -> async { return Accepted }
        ValidatePublicKey = fun _ _ _ -> async { return Rejected }
        OnExec = onExec
    }
    let worker = Async.StartAsTask(async {
        use! client = listener.AcceptTcpClientAsync() |> Async.AwaitTask
        do! ExecServer.handleClient client config callbacks ignore CancellationToken.None
    })
    listener, port, worker

let private connect port =
    let config = { ClientConfig.defaults with Username = "test"; HostKeyVerification = AcceptAll }
    let auth: ClientAuth.ClientAuthConfig = { Username = "test"; Methods = [ ClientAuth.PasswordAuth "password" ] }
    match Client.connectAsync "127.0.0.1" port config auth |> Async.RunSynchronously with
    | Ok client -> client
    | Error e -> failwithf "connect: %A" e

[<Fact>]
let ``authentication deadline includes stalled version exchange`` () =
    let config = { ServerConfig.defaults with AuthTimeout = TimeSpan.FromMilliseconds 200.0 }
    let listener, port, worker = server config (fun _ -> Task.FromResult 0)
    use listener = listener
    use peer = new TcpClient()
    peer.Connect(IPAddress.Loopback, port)
    Assert.True(worker.Wait(TimeSpan.FromSeconds 5.0), "version exchange did not time out")

[<Fact>]
let ``idle deadline closes an authenticated connection`` () =
    let config = { ServerConfig.defaults with HostKeys = [ Crypto.createEd25519HostKey() ]; IdleTimeout = TimeSpan.FromMilliseconds 300.0 }
    let listener, port, worker = server config (fun _ -> Task.FromResult 0)
    use listener = listener
    let client = connect port
    use socket = client.TcpClient
    Assert.True(worker.Wait(TimeSpan.FromSeconds 5.0), "authenticated idle session did not time out")

[<Fact>]
let ``exec input returns credit only after read and pending reads end on teardown`` () =
    let gate = TaskCompletionSource<unit>(TaskCreationOptions.RunContinuationsAsynchronously)
    let readStarted = TaskCompletionSource<unit>(TaskCreationOptions.RunContinuationsAsynchronously)
    let readEnded = TaskCompletionSource<unit>(TaskCreationOptions.RunContinuationsAsynchronously)
    let onExec (exec: ExecChannel) = task {
        do! gate.Task
        let buffer = Array.zeroCreate<byte> 3
        let! count = exec.Input.ReadAsync(buffer, 0, 3, CancellationToken.None)
        if count <> 3 then failwithf "read %d" count
        readStarted.TrySetResult() |> ignore
        try
            let! _ = exec.Input.ReadAsync(buffer, 0, 3, CancellationToken.None)
            ()
        finally
            readEnded.TrySetResult() |> ignore
        return 0
    }
    let config = { ServerConfig.defaults with HostKeys = [ Crypto.createEd25519HostKey() ] }
    let listener, port, worker = server config onExec
    use listener = listener
    let client = connect port
    use socket = client.TcpClient
    let id = match Client.openChannel client |> Async.RunSynchronously with Ok id -> id | Error e -> failwithf "%A" e
    match Client.requestExec client id "read" |> Async.RunSynchronously with Ok () -> () | Error e -> failwithf "%A" e
    match Client.sendData client id [| 1uy; 2uy; 3uy |] |> Async.RunSynchronously with Ok () -> () | Error e -> failwithf "%A" e
    Assert.False(socket.Client.Poll(200000, SelectMode.SelectRead), "credit returned before consumption")
    gate.TrySetResult() |> ignore
    Assert.True(readStarted.Task.Wait(TimeSpan.FromSeconds 5.0), "input was not delivered")
    let received = Transport.receiveMessage client.Stream (!client.Context).TransportState |> Async.RunSynchronously
    match received with
    | Ok (ChannelWindowAdjust (_, 3u), _) -> ()
    | other -> failwithf "expected consumed credit, got %A" other
    socket.Close()
    Assert.True(worker.Wait(TimeSpan.FromSeconds 5.0), "session did not end")
    Assert.True(readEnded.Task.Wait(TimeSpan.FromSeconds 5.0), "pending input read did not end")
