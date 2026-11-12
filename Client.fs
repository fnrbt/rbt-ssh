namespace Rbt.Ssh

open System
open System.Collections.Generic
open System.Net.Sockets
open System.Threading

/// Connection-protocol state shared by the independent reader and writers.
type ClientContext = {
    TransportState: TransportState
    KexState: KexState
    ChannelManager: Channel.ChannelManager
    State: SessionState
    Username: string
}

type ClientRuntime = {
    /// Serializes complete packet writes, including their outbound cursor publication.
    SendGate: SemaphoreSlim
    /// Only one reader may consume a reply or an incoming packet at a time.
    ReceiveGate: SemaphoreSlim
    ContextSync: obj
    /// True when credit was returned during a request-reply wait.
    PendingMessages: Queue<SshMessage * bool>
    /// A wire read started by a sender waiting for window credit. The next
    /// ReceiveGate holder takes its result before reading the wire itself.
    mutable InFlightRead: Tasks.Task<SshResult<SshMessage>> option
    Closed: CancellationTokenSource
}

module ClientRuntime =
    let create () = {
        SendGate = new SemaphoreSlim(1, 1)
        ReceiveGate = new SemaphoreSlim(1, 1)
        ContextSync = obj ()
        PendingMessages = Queue<SshMessage * bool>()
        InFlightRead = None
        Closed = new CancellationTokenSource()
    }

type SshClient = {
    TcpClient: TcpClient
    Stream: NetworkStream
    Context: ClientContext ref
    Runtime: ClientRuntime
}

/// Callbacks for receiving data from the server
type ClientCallbacks = {
    OnStdout: uint32 -> byte[] -> Async<unit>
    OnStderr: uint32 -> byte[] -> Async<unit>
    OnExit: uint32 -> uint32 -> Async<unit>
    OnChannelClose: uint32 -> Async<unit>
}

module Client =

    let private snapshot (client: SshClient) =
        lock client.Runtime.ContextSync (fun () -> !client.Context)

    let private update (client: SshClient) change =
        lock client.Runtime.ContextSync (fun () -> client.Context := change !client.Context)

    let private stop (client: SshClient) =
        lock client.Runtime.ContextSync (fun () ->
            client.Context := { !client.Context with State = SessionState.Disconnected }
            if not client.Runtime.Closed.IsCancellationRequested then client.Runtime.Closed.Cancel())
        let manager = (snapshot client).ChannelManager
        let ids = lock manager.Sync (fun () -> manager.Channels.Keys |> Seq.toArray)
        for id in ids do Channel.ChannelManager.removeChannel manager id
        // Interrupt any outstanding read as well as credit waiters.
        client.TcpClient.Dispose()

    /// All connection-protocol writes must go through this gate. Publication
    /// merges only outbound cursors into the latest context, never a stale read
    /// cursor or an obsolete channel-manager snapshot.
    let private send (client: SshClient) message = async {
        try
            do! client.Runtime.SendGate.WaitAsync(client.Runtime.Closed.Token) |> Async.AwaitTask
            try
                let state = (snapshot client).TransportState
                let! result = Transport.sendMessage client.Stream state message
                match result with
                | Ok next ->
                    update client (fun ctx ->
                        { ctx with TransportState = Transport.adoptWriteCursors ctx.TransportState next })
                    return Ok ()
                | Error e ->
                    stop client
                    return Error e
            finally
                client.Runtime.SendGate.Release() |> ignore
        with
        | :? OperationCanceledException -> return Error (ConnectionError "Connection closed")
        | ex ->
            stop client
            return Error (ConnectionError ex.Message)
    }

    /// Read one packet from the wire. The wire reader may overlap a writer;
    /// only the inbound sequence and IV from its result are published. At
    /// most one read is outstanding: callers hold ReceiveGate, or start the
    /// read under it as InFlightRead.
    let private readPacket (client: SshClient) = async {
        try
            let state = (snapshot client).TransportState
            let! result = Transport.receiveMessage client.Stream state
            match result with
            | Error e ->
                stop client
                return Error e
            | Ok (msg, next) ->
                update client (fun ctx ->
                    { ctx with TransportState = Transport.adoptReadCursors ctx.TransportState next })
                return Ok msg
        with ex ->
            stop client
            return Error (ConnectionError ex.Message)
    }

    /// Called with ReceiveGate held. Takes the result of a read a credit
    /// waiter left in flight before reading the wire.
    let private readWire (client: SshClient) = async {
        match client.Runtime.InFlightRead with
        | Some read ->
            client.Runtime.InFlightRead <- None
            return! Async.AwaitTask read
        | None -> return! readPacket client
    }

    let private receive (client: SshClient) = async {
        try
            do! client.Runtime.ReceiveGate.WaitAsync() |> Async.AwaitTask
            try
                if client.Runtime.PendingMessages.Count <> 0 then
                    return Ok (client.Runtime.PendingMessages.Dequeue())
                else if (snapshot client).State = SessionState.Disconnected then
                    return Error (ConnectionError "Connection closed")
                else
                    let! result = readWire client
                    return Result.map (fun msg -> msg, false) result
            finally
                client.Runtime.ReceiveGate.Release() |> ignore
        with :? OperationCanceledException -> return Error (ConnectionError "Connection closed")
    }

    /// Connect and authenticate within one deadline covering TCP, banner,
    /// key exchange and user authentication. Closing the socket interrupts
    /// pending stream reads when either the deadline or caller cancels.
    let connectAsync (host: string) (port: int) (config: ClientConfig)
        (authConfig: ClientAuth.ClientAuthConfig) = async {
        let! callerToken = Async.CancellationToken
        use deadline = CancellationTokenSource.CreateLinkedTokenSource(callerToken)
        deadline.CancelAfter(config.ConnectTimeout)
        let client = new TcpClient()
        let mutable connected = false
        try
            try
                let handshake = async {
                    do! client.ConnectAsync(host, port, deadline.Token).AsTask() |> Async.AwaitTask
                    let stream = client.GetStream()
                    let transportState = TransportState.createClient config.ClientVersion
                    match! Transport.exchangeVersionsAsClient stream config.ClientVersion with
                    | Error e -> return Error e
                    | Ok serverVersion ->
                        let withVersions = {
                            transportState with ServerVersion = serverVersion; ClientVersion = Some config.ClientVersion }
                        match! ClientKeyExchange.handleKeyExchange stream withVersions config.HostKeyVerification with
                        | Error e -> return Error e
                        | Ok (transportAfterKex, kexState, _) ->
                            match kexState.SessionId with
                            | None -> return Error (ProtocolError "No session ID after key exchange")
                            | Some sessionId ->
                                match! ClientAuth.authenticate stream transportAfterKex sessionId authConfig with
                                | Error e -> return Error e
                                | Ok transportAfterAuth ->
                                    let ctx = {
                                        TransportState = transportAfterAuth
                                        KexState = kexState
                                        ChannelManager = Channel.ChannelManager.create()
                                        State = Authenticated
                                        Username = authConfig.Username
                                    }
                                    return Ok {
                                        TcpClient = client
                                        Stream = stream
                                        Context = ref ctx
                                        Runtime = ClientRuntime.create()
                                    }
                }
                let! result = Async.StartAsTask(handshake, cancellationToken = deadline.Token) |> Async.AwaitTask
                connected <- Result.isOk result
                return result
            with
            | :? OperationCanceledException ->
                return Error (ConnectionError (if callerToken.IsCancellationRequested then "Connection cancelled" else "Connection timed out"))
            | ex -> return Error (ConnectionError ex.Message)
        finally
            if not connected then client.Dispose()
    }

    let private manager (client: SshClient) = (snapshot client).ChannelManager

    /// Process window grants even during reply waits, to unblock writers.
    let private windowGrant (client: SshClient) recipient bytes =
        Channel.handleWindowAdjust (manager client) recipient bytes |> ignore

    /// Return receive credit even for data buffered while awaiting a reply.
    let private replenish (client: SshClient) recipient length = async {
        if length = 0 then return Ok ()
        else
            match Channel.ChannelManager.getChannel (manager client) recipient with
            | None -> return Error (ChannelError $"Unknown channel: {recipient}")
            | Some channel ->
                Channel.ChannelManager.updateChannel (manager client) recipient (fun ch ->
                    { ch with LocalWindowSize = ch.LocalWindowSize + uint32 length }) |> ignore
                return! send client (ChannelWindowAdjust(channel.RemoteChannel, uint32 length))
    }

    /// Handle a message no reader has asked for, with ReceiveGate held:
    /// window grants are applied now, every channel event is retained in
    /// arrival order for the next receiveOne, and buffered data returns its
    /// receive credit at once so the peer keeps sending. A close of
    /// `channelId` is acknowledged and the channel removed immediately, to
    /// release its senders; the result is then `closedError`.
    let private absorb (client: SshClient) (channelId: uint32) (closedError: string)
        (defer: SshMessage * bool -> unit) (msg: SshMessage) = async {
        match msg with
        | ChannelWindowAdjust(recipient, bytes) ->
            windowGrant client recipient bytes
            return Ok ()
        | ChannelData(recipient, data)
        | ChannelExtendedData(recipient, _, data) ->
            match Channel.receiveDataCredit (manager client) recipient data.Length with
            | Error e -> return Error e
            | Ok () ->
                match! replenish client recipient data.Length with
                | Error e -> return Error e
                | Ok () ->
                    defer (msg, true)
                    return Ok ()
        | GlobalRequest(_, true, _) -> return! send client RequestFailure
        | ChannelClose recipient when recipient = channelId ->
            // Earlier data has already returned credit; replay only its
            // callback and the close callback.
            let! ack = async {
                match Channel.ChannelManager.getChannel (manager client) recipient with
                | Some channel when not channel.IsClosed -> return! send client (ChannelClose(channel.RemoteChannel))
                | _ -> return Ok ()
            }
            Channel.ChannelManager.removeChannel (manager client) recipient
            defer (msg, false)
            return (match ack with Error e -> Error e | Ok () -> Error (ChannelError closedError))
        | Disconnect(_, description, _) ->
            defer (msg, false)
            stop client
            return Error (ConnectionError $"Server disconnected: {description}")
        | _ ->
            defer (msg, false)
            return Ok ()
    }

    /// Wait for a particular reply while retaining every interleaved channel
    /// event in arrival order for the next receiveOne. The gate is held from
    /// before sending the request through receipt of its reply, so another
    /// consumer cannot accidentally take that reply.
    let private awaitReply (client: SshClient) (channelId: uint32)
        (accept: SshMessage -> SshResult<'a> option) = async {
        let deferred = ResizeArray<SshMessage * bool>()
        try
            let mutable answer = None
            while answer.IsNone do
                match! readWire client with
                | Error e -> answer <- Some (Error e)
                | Ok msg ->
                    match accept msg with
                    | Some result -> answer <- Some result
                    | None ->
                        match! absorb client channelId "Channel closed before reply" deferred.Add msg with
                        | Error e -> answer <- Some (Error e)
                        | Ok () -> ()
            return answer.Value
        finally
            for msg in deferred do client.Runtime.PendingMessages.Enqueue(msg)
    }

    /// Wait for the peer to grant window credit (`signal`). The grant arrives
    /// as a CHANNEL_WINDOW_ADJUST, which only a reader processes, so when no
    /// one else holds ReceiveGate the sender reads for itself. It never blocks
    /// on the wire while holding the gate: the read is left in flight and the
    /// gate released, so a concurrent request or receiveOne can still take the
    /// gate and consume that read's result. Returns after one step; the caller
    /// asks for credit again.
    let private awaitCredit (client: SshClient) (channelId: uint32)
        (signal: Tasks.TaskCompletionSource<unit>) (ct: CancellationToken) = async {
        let runtime = client.Runtime
        let cancelled = Error (ChannelError "Channel send cancelled")
        use gateWait = CancellationTokenSource.CreateLinkedTokenSource(ct)
        let gate = runtime.ReceiveGate.WaitAsync(gateWait.Token)
        let! first = Tasks.Task.WhenAny(signal.Task :> Tasks.Task, gate) |> Async.AwaitTask
        if not (obj.ReferenceEquals(first, gate)) then
            // Credit arrived; give back the gate if it was acquired anyway.
            gateWait.Cancel()
            let! acquired = task {
                try
                    do! gate
                    return true
                with :? OperationCanceledException -> return false } |> Async.AwaitTask
            if acquired then runtime.ReceiveGate.Release() |> ignore
            return Ok ()
        elif gate.IsCanceled then return cancelled
        else
            let! step = async {
                try
                    if signal.Task.IsCompleted then return Ok None
                    else
                        match runtime.InFlightRead with
                        | Some read when read.IsCompleted ->
                            runtime.InFlightRead <- None
                            match read.Result with
                            | Error e -> return Error e
                            | Ok msg ->
                                let! absorbed =
                                    absorb client channelId "Channel closed while sending"
                                        runtime.PendingMessages.Enqueue msg
                                return Result.map (fun () -> None) absorbed
                        | Some read -> return Ok (Some read)
                        | None ->
                            let read = Async.StartAsTask(readPacket client)
                            runtime.InFlightRead <- Some read
                            return Ok (Some read)
                finally
                    runtime.ReceiveGate.Release() |> ignore
            }
            match step with
            | Error e -> return Error e
            | Ok None -> return Ok ()
            | Ok (Some read) ->
                try
                    let! _ = Tasks.Task.WhenAny(signal.Task :> Tasks.Task, read.WaitAsync(ct) :> Tasks.Task) |> Async.AwaitTask
                    return (if ct.IsCancellationRequested && not signal.Task.IsCompleted then cancelled else Ok ())
                with :? OperationCanceledException -> return cancelled
    }

    /// Open a session channel.
    let openChannel (client: SshClient) = async {
        try
            do! client.Runtime.ReceiveGate.WaitAsync(client.Runtime.Closed.Token) |> Async.AwaitTask
            try
                let previous = manager client
                let (nextManager, channel) =
                    Channel.ChannelManager.allocateChannel previous "session" 0u 0u 0u
                update client (fun ctx -> { ctx with ChannelManager = nextManager })
                let openMsg = ChannelOpen("session", channel.LocalChannel,
                                          Constants.DefaultWindowSize, Constants.DefaultMaxPacketSize, [||])
                match! send client openMsg with
                | Error e ->
                    Channel.ChannelManager.removeChannel nextManager channel.LocalChannel
                    return Error e
                | Ok () ->
                    let accept = function
                        | ChannelOpenConfirmation(recipient, remote, window, packetSize, _) when recipient = channel.LocalChannel ->
                            Channel.ChannelManager.updateChannel nextManager recipient (fun ch ->
                                { ch with RemoteChannel = remote; RemoteWindowSize = window; RemoteMaxPacketSize = packetSize }) |> ignore
                            Some (Ok recipient)
                        | ChannelOpenFailure(recipient, code, description, _) when recipient = channel.LocalChannel ->
                            Some (Error (ChannelError $"Channel open rejected ({code}): {description}"))
                        | _ -> None
                    let! answer = awaitReply client channel.LocalChannel accept
                    if Result.isError answer then Channel.ChannelManager.removeChannel nextManager channel.LocalChannel
                    return answer
            finally
                client.Runtime.ReceiveGate.Release() |> ignore
        with :? OperationCanceledException -> return Error (ConnectionError "Connection closed")
    }

    /// A channel request completes only on its own CHANNEL_SUCCESS or FAILURE.
    /// Earlier data, exit status, EOF and close are replayed exactly once.
    let private sendChannelRequest (client: SshClient) (channelId: uint32)
        (requestType: string) (requestData: byte[]) = async {
        try
            do! client.Runtime.ReceiveGate.WaitAsync(client.Runtime.Closed.Token) |> Async.AwaitTask
            try
                match Channel.ChannelManager.getChannel (manager client) channelId with
                | None -> return Error (ChannelError "Unknown channel")
                | Some channel ->
                    let msg = ChannelRequest(channel.RemoteChannel, requestType, true, requestData)
                    match! send client msg with
                    | Error e -> return Error e
                    | Ok () ->
                        return! awaitReply client channelId (function
                            | ChannelSuccess recipient when recipient = channelId -> Some (Ok ())
                            | ChannelFailure recipient when recipient = channelId ->
                                Some (Error (ChannelError "Channel request rejected"))
                            | _ -> None)
            finally
                client.Runtime.ReceiveGate.Release() |> ignore
        with :? OperationCanceledException -> return Error (ConnectionError "Connection closed")
    }

    /// Request a PTY on a channel.
    let requestPty (client: SshClient) (channelId: uint32)
        (term: string) (widthCols: uint32) (heightRows: uint32) = async {
        let data = Packet.buildChannelRequestData (PtyReq(term, widthCols, heightRows, 0u, 0u, [||]))
        return! sendChannelRequest client channelId "pty-req" data
    }

    /// Request a shell on a channel.
    let requestShell client channelId = sendChannelRequest client channelId "shell" [||]

    /// Request exec on a channel.
    let requestExec client channelId command =
        sendChannelRequest client channelId "exec" (Packet.buildChannelRequestData (Exec(command)))

    /// Send data, waiting for window credit until the channel closes, the
    /// connection ends or the calling async computation is cancelled. While
    /// waiting it processes incoming messages itself when no other reader is
    /// active, so a caller may write everything before it starts reading.
    let sendData (client: SshClient) (channelId: uint32) (data: byte[]) = async {
        let! callerToken = Async.CancellationToken
        use cancellation = CancellationTokenSource.CreateLinkedTokenSource(callerToken, client.Runtime.Closed.Token)
        let mutable position = 0
        let mutable failure : SshResult<unit> option = None
        while failure.IsNone && position < data.Length do
            match Channel.acquireOutboundCredit (manager client) channelId data position with
            | Error e -> failure <- Some (Error e)
            | Ok (Channel.Waiting signal) ->
                match! awaitCredit client channelId signal cancellation.Token with
                | Error e -> failure <- Some (Error e)
                | Ok () -> ()
            | Ok (Channel.Granted chunk) ->
                match Channel.ChannelManager.getChannel (manager client) channelId with
                | None -> failure <- Some (Error (ChannelError $"Unknown channel: {channelId}"))
                | Some channel ->
                    match! send client (ChannelData(channel.RemoteChannel, chunk)) with
                    | Error e -> failure <- Some (Error e)
                    | Ok () -> position <- position + chunk.Length
        return defaultArg failure (Ok ())
    }

    /// Send EOF on a channel.
    let sendEof (client: SshClient) (channelId: uint32) = async {
        match Channel.ChannelManager.getChannel (manager client) channelId with
        | None -> return Error (ChannelError "Unknown channel")
        | Some channel -> return! send client (ChannelEof(channel.RemoteChannel))
    }

    /// Process one incoming event, including events buffered during a request.
    let receiveOne (client: SshClient) (callbacks: ClientCallbacks) = async {
        match! receive client with
        | Error e -> return Error e
        | Ok (msg, accounted) ->
            match msg with
            | ChannelData(recipient, data) ->
                let credit =
                    if accounted then Ok ()
                    else Channel.receiveDataCredit (manager client) recipient data.Length
                match credit with
                | Error e -> return Error e
                | Ok () ->
                    do! callbacks.OnStdout recipient data
                    if accounted then return Ok true
                    else
                        match! replenish client recipient data.Length with
                        | Ok () -> return Ok true
                        | Error e -> return Error e
            | ChannelExtendedData(recipient, _, data) ->
                let credit =
                    if accounted then Ok ()
                    else Channel.receiveDataCredit (manager client) recipient data.Length
                match credit with
                | Error e -> return Error e
                | Ok () ->
                    do! callbacks.OnStderr recipient data
                    if accounted then return Ok true
                    else
                        match! replenish client recipient data.Length with
                        | Ok () -> return Ok true
                        | Error e -> return Error e
            | ChannelRequest(recipient, "exit-status", _, data) ->
                if data.Length <> 4 then
                    stop client
                    return Error (ProtocolError "Invalid exit-status request")
                else
                    do! callbacks.OnExit recipient (Packet.readUint32 data 0)
                    return Ok true
            | ChannelEof _ -> return Ok true
            | ChannelClose recipient ->
                let! reply =
                    match Channel.ChannelManager.getChannel (manager client) recipient with
                    | Some channel when not channel.IsClosed ->
                        send client (ChannelClose(channel.RemoteChannel))
                    | _ -> async { return Ok () }
                Channel.ChannelManager.removeChannel (manager client) recipient
                match reply with
                | Error error -> return Error error
                | Ok () ->
                    do! callbacks.OnChannelClose recipient
                    return Ok false
            | ChannelWindowAdjust(recipient, bytes) ->
                windowGrant client recipient bytes
                return Ok true
            | Disconnect(_, description, _) ->
                stop client
                return Error (ConnectionError $"Server disconnected: {description}")
            | _ -> return Ok true
    }

    /// Run the receive loop until channel close or an error.
    let receiveLoop (client: SshClient) (callbacks: ClientCallbacks) = async {
        let mutable running = true
        let mutable error = None
        while running do
            match! receiveOne client callbacks with
            | Ok true -> ()
            | Ok false -> running <- false
            | Error e ->
                stop client
                error <- Some e
                running <- false
        return match error with Some e -> Error e | None -> Ok ()
    }

    /// Execute a command and collect output. A close without exit-status is
    /// not a successful command completion.
    let exec (client: SshClient) (command: string) = async {
        match! openChannel client with
        | Error e -> return Error e
        | Ok channelId ->
            match Channel.ChannelManager.getChannel (manager client) channelId with
            | None -> return Error (ChannelError "Unknown channel")
            | Some channel ->
                let request = ChannelRequest(channel.RemoteChannel, "exec", false,
                                             Packet.buildChannelRequestData (Exec(command)))
                match! send client request with
                | Error e -> return Error e
                | Ok () ->
                    let stdout = ResizeArray<byte>()
                    let stderr = ResizeArray<byte>()
                    let mutable exitCode = None
                    let callbacks = {
                        OnStdout = fun recipient data -> async {
                            if recipient = channelId then stdout.AddRange(data) }
                        OnStderr = fun recipient data -> async {
                            if recipient = channelId then stderr.AddRange(data) }
                        OnExit = fun recipient code -> async {
                            if recipient = channelId then exitCode <- Some code }
                        OnChannelClose = fun _ -> async { () }
                    }
                    match! receiveLoop client callbacks with
                    | Error e -> return Error e
                    | Ok () ->
                        match exitCode with
                        | None -> return Error (ChannelError "Channel closed without exit status")
                        | Some code -> return Ok (code, stdout.ToArray(), stderr.ToArray())
    }

    /// Disconnect gracefully and unblock pending channel writers/readers.
    let disconnect (client: SshClient) = async {
        if (snapshot client).State <> SessionState.Disconnected then
            let msg = Disconnect(DisconnectReason.SSH_DISCONNECT_BY_APPLICATION, "Client disconnecting", "")
            let! _ = send client msg
            ()
        stop client
    }
