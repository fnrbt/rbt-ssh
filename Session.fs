namespace Rbt.Ssh

open System
open System.Net.Sockets
open System.Threading

type SessionContext = {
    TransportState: TransportState
    KexState: KexState
    ChannelManager: Channel.ChannelManager
    AuthState: Auth.AuthState option
    State: SessionState
    Username: string option
}

/// Per-session serialization. `Send` guards wire writes, `State` guards the
/// shared transport cursors. Both critical sections are short and contain no
/// awaits.
type SessionLocks = {
    Send: SemaphoreSlim
    State: obj
}

module SessionLocks =
    let create () = { Send = new SemaphoreSlim(1, 1); State = obj () }

type ChannelCallbackFactory =
    NetworkStream -> SessionContext ref -> SessionLocks -> Auth.AuthState -> ChannelCallbacks

module Session =

    let create serverVersion = {
        TransportState = TransportState.create serverVersion
        KexState = KexState.empty
        ChannelManager = Channel.ChannelManager.create()
        AuthState = None
        State = VersionExchange
        Username = None
    }

    let private withSendLock (locks: SessionLocks) work = async {
        do! locks.Send.WaitAsync() |> Async.AwaitTask
        try
            return! work()
        finally
            locks.Send.Release() |> ignore
    }

    /// Publish the state a wire operation produced, adopting only the
    /// direction that operation advanced. The read-merge-write runs under
    /// `locks.State`, so a concurrent publish cannot interleave between the
    /// read and the write.
    let private publishTransport
        (ctx: SessionContext ref)
        (locks: SessionLocks)
        (adopt: TransportState -> TransportState -> TransportState)
        (outcome: TransportState) =
        lock locks.State (fun () ->
            let latest = ctx.Value
            ctx.Value <- { latest with TransportState = adopt latest.TransportState outcome })

    let private publishContext (ctx: SessionContext ref) (locks: SessionLocks) update =
        lock locks.State (fun () -> ctx.Value <- update ctx.Value)

    let private sendMessageRef
        (stream: NetworkStream)
        (ctx: SessionContext ref)
        (locks: SessionLocks)
        (message: SshMessage) = async {
        return!
            withSendLock locks (fun () -> async {
                let current = !ctx
                let! sent = Transport.sendMessage stream current.TransportState message
                match sent with
                | Error e -> return Error e
                | Ok transport ->
                    publishTransport ctx locks Transport.adoptWriteCursors transport
                    return Ok ()
            })
    }

    let sendDataRef
        (stream: NetworkStream)
        (ctx: SessionContext ref)
        (locks: SessionLocks)
        (channelId: uint32)
        (data: byte[])
        (ct: CancellationToken) = async {
        // Credit is acquired before taking the send lock and awaited while not
        // holding it: the peer's CHANNEL_WINDOW_ADJUST arrives on the receive
        // loop, which needs that same lock to publish its own sends.
        let mutable position = 0
        let mutable failure : SshResult<unit> option = None
        while failure.IsNone && position < data.Length do
            match Channel.acquireOutboundCredit (!ctx).ChannelManager channelId data position with
            | Error e -> failure <- Some (Error e)
            | Ok (Channel.Waiting signal) ->
                match! Channel.waitForCredit signal ct with
                | Error e -> failure <- Some (Error e)
                | Ok () -> ()
            | Ok (Channel.Granted chunk) ->
                let! sent =
                    withSendLock locks (fun () -> async {
                        let current = !ctx
                        match Channel.ChannelManager.getChannel current.ChannelManager channelId with
                        | None -> return Error (ChannelError $"Unknown channel: {channelId}")
                        | Some channel ->
                            let! result =
                                Transport.sendMessage
                                    stream
                                    current.TransportState
                                    (ChannelData(channel.RemoteChannel, chunk))
                            match result with
                            | Error e -> return Error e
                            | Ok transport ->
                                publishTransport ctx locks Transport.adoptWriteCursors transport
                                return Ok ()
                    })
                match sent with
                | Error e -> failure <- Some (Error e)
                | Ok () -> position <- position + chunk.Length
        match failure with
        | Some result -> return result
        | None -> return Ok ()
    }

    let sendExtendedDataRef
        (stream: NetworkStream)
        (ctx: SessionContext ref)
        (locks: SessionLocks)
        (channelId: uint32)
        (dataTypeCode: uint32)
        (data: byte[])
        (ct: CancellationToken) = async {
        let mutable position = 0
        let mutable failure : SshResult<unit> option = None
        while failure.IsNone && position < data.Length do
            match Channel.acquireOutboundCredit (!ctx).ChannelManager channelId data position with
            | Error e -> failure <- Some (Error e)
            | Ok (Channel.Waiting signal) ->
                match! Channel.waitForCredit signal ct with
                | Error e -> failure <- Some (Error e)
                | Ok () -> ()
            | Ok (Channel.Granted chunk) ->
                let! sent =
                    withSendLock locks (fun () -> async {
                        let current = !ctx
                        match Channel.ChannelManager.getChannel current.ChannelManager channelId with
                        | None -> return Error (ChannelError $"Unknown channel: {channelId}")
                        | Some channel ->
                            let! result =
                                Transport.sendMessage
                                    stream
                                    current.TransportState
                                    (ChannelExtendedData(channel.RemoteChannel, dataTypeCode, chunk))
                            match result with
                            | Error e -> return Error e
                            | Ok transport ->
                                publishTransport ctx locks Transport.adoptWriteCursors transport
                                return Ok ()
                    })
                match sent with
                | Error e -> failure <- Some (Error e)
                | Ok () -> position <- position + chunk.Length
        match failure with
        | Some result -> return result
        | None -> return Ok ()
    }

    let closeChannelWithStatusRef
        (stream: NetworkStream)
        (ctx: SessionContext ref)
        (locks: SessionLocks)
        (channelId: uint32)
        (exitStatus: uint32) = async {
        return!
            withSendLock locks (fun () -> async {
                let current = !ctx
                let! statusResult = Channel.sendExitStatus stream current.TransportState current.ChannelManager channelId exitStatus
                match statusResult with
                | Error e -> return Error e
                | Ok stateAfterStatus ->
                    let! eofResult = Channel.sendChannelEof stream stateAfterStatus current.ChannelManager channelId
                    match eofResult with
                    | Error e ->
                        publishTransport ctx locks Transport.adoptWriteCursors stateAfterStatus
                        return Error e
                    | Ok stateAfterEof ->
                        let! closeResult = Channel.closeChannel stream stateAfterEof current.ChannelManager channelId
                        match closeResult with
                        | Error e ->
                            publishTransport ctx locks Transport.adoptWriteCursors stateAfterEof
                            return Error e
                        | Ok stateAfterClose ->
                            publishTransport ctx locks Transport.adoptWriteCursors stateAfterClose
                            return Ok ()
            })
    }
    /// Return receive credit only after application consumption.
    let replenishInputRef
        (stream: NetworkStream)
        (ctx: SessionContext ref)
        (locks: SessionLocks)
        (channelId: uint32)
        (bytes: uint32) = async {
        if bytes = 0u then return Ok ()
        else
            return! withSendLock locks (fun () -> async {
                let current = !ctx
                let! result = Channel.sendWindowAdjust stream current.TransportState current.ChannelManager channelId bytes
                match result with
                | Error e -> return Error e
                | Ok transport ->
                    publishTransport ctx locks Transport.adoptWriteCursors transport
                    return Ok ()
            })
    }


    let private handleMessageRef
        (stream: NetworkStream)
        (ctx: SessionContext ref)
        (locks: SessionLocks)
        (msg: SshMessage)
        (channelCallbacks: ChannelCallbacks) = async {

        match msg with
        | Disconnect(reason, description, _) ->
            publishContext ctx locks (fun latest -> { latest with State = SessionState.Disconnected })
            return Ok (), Some (SshError.Disconnected(reason, description))

        | Ignore _ | Unimplemented _ | Debug _ ->
            return Ok (), None

        | GlobalRequest(_, wantReply, _) ->
            if wantReply then
                let! sent = sendMessageRef stream ctx locks RequestFailure
                return sent, None
            else
                return Ok (), None

        | ChannelOpen(channelType, senderChannel, initialWindowSize, maximumPacketSize, data) ->
            let! result =
                withSendLock locks (fun () -> async {
                    let current = !ctx
                    let! result =
                        Channel.handleChannelOpen
                            stream current.TransportState current.ChannelManager
                            channelType senderChannel initialWindowSize maximumPacketSize data
                    match result with
                    | Error e -> return Error e
                    | Ok (transport, manager, _) ->
                        publishContext ctx locks (fun latest ->
                            { latest with
                                TransportState = Transport.adoptWriteCursors latest.TransportState transport
                                ChannelManager = manager })
                        return Ok ()
                })
            match result with
            | Error e -> return Error e, None
            | Ok () -> return Ok (), None

        | ChannelRequest(recipientChannel, requestType, wantReply, data) ->
            let current = !ctx
            let! result =
                Channel.handleChannelRequest
                    stream current.TransportState current.ChannelManager
                    channelCallbacks recipientChannel requestType wantReply data
            match result with
            | Error e -> return Error e, None
            | Ok (_, manager, success, replyChannelOpt) ->
                publishContext ctx locks (fun latest -> { latest with ChannelManager = manager })
                match replyChannelOpt with
                | Some remoteChannel ->
                    let reply = if success then ChannelSuccess(remoteChannel) else ChannelFailure(remoteChannel)
                    let! sent = sendMessageRef stream ctx locks reply
                    return sent, None
                | None ->
                    return Ok (), None

        | ChannelData(recipientChannel, data) ->
            let current = !ctx
            let! result = Channel.handleChannelData current.ChannelManager channelCallbacks recipientChannel data
            match result with
            | Error e -> return Error e, None
            | Ok manager ->
                publishContext ctx locks (fun latest -> { latest with ChannelManager = manager })
                let deferred = lock manager.Sync (fun () -> manager.DeferredInput.Contains recipientChannel)
                if deferred then return Ok (), None
                else
                    let! adjusted = replenishInputRef stream ctx locks recipientChannel (uint32 data.Length)
                    return adjusted, None

        | ChannelExtendedData(recipientChannel, dataTypeCode, data) ->
            let current = !ctx
            let! result = Channel.handleChannelExtendedData current.ChannelManager channelCallbacks recipientChannel dataTypeCode data
            match result with
            | Error e -> return Error e, None
            | Ok manager ->
                publishContext ctx locks (fun latest -> { latest with ChannelManager = manager })
                let! adjusted = replenishInputRef stream ctx locks recipientChannel (uint32 data.Length)
                return adjusted, None

        | ChannelEof(recipientChannel) ->
            let current = !ctx
            let! result = Channel.handleChannelEof current.ChannelManager channelCallbacks recipientChannel
            match result with
            | Error e -> return Error e, None
            | Ok manager ->
                publishContext ctx locks (fun latest -> { latest with ChannelManager = manager })
                return Ok (), None

        | ChannelClose(recipientChannel) ->
            let! result =
                withSendLock locks (fun () -> async {
                    let current = !ctx
                    let! result = Channel.handleChannelClose stream current.TransportState current.ChannelManager channelCallbacks recipientChannel
                    match result with
                    | Error e -> return Error e
                    | Ok (transport, manager) ->
                        publishContext ctx locks (fun latest ->
                            { latest with
                                TransportState = Transport.adoptWriteCursors latest.TransportState transport
                                ChannelManager = manager })
                        return Ok ()
                })
            match result with
            | Error e -> return Error e, None
            | Ok () -> return Ok (), None

        | ChannelWindowAdjust(recipientChannel, bytesToAdd) ->
            let current = !ctx
            match Channel.handleWindowAdjust current.ChannelManager recipientChannel bytesToAdd with
            | Error e -> return Error e, None
            | Ok manager ->
                publishContext ctx locks (fun latest -> { latest with ChannelManager = manager })
                return Ok (), None

        | ChannelSuccess _ | ChannelFailure _ ->
            return Ok (), None

        | UserAuthRequest _ ->
            if (!ctx).State = Authenticated then
                return Error (ProtocolError "Unexpected USERAUTH_REQUEST after authentication"), None
            else
                return Error (ProtocolError "Auth state not initialized"), None

        | _ ->
            let sequence = (!ctx).TransportState.ClientToServerSequence - 1u
            let! sent = sendMessageRef stream ctx locks (Unimplemented sequence)
            return sent, None
    }

    let private runMessageLoopWithTimeout
        (stream: NetworkStream)
        (ctx: SessionContext ref)
        (locks: SessionLocks)
        (channelCallbacks: ChannelCallbacks)
        (idleTimeout: (CancellationTokenSource * TimeSpan) option) = async {

        let rec loop () = async {
            let current = !ctx
            if current.State = SessionState.Disconnected then
                return Ok current
            else
                let! received = Transport.receiveMessage stream current.TransportState
                match received with
                | Error e -> return Error e
                | Ok (msg, transportAfterReceive) ->
                    match idleTimeout with
                    | Some (timer, timeout) -> timer.CancelAfter(timeout)
                    | None -> ()
                    publishTransport ctx locks Transport.adoptReadCursors transportAfterReceive
                    let! handled = handleMessageRef stream ctx locks msg channelCallbacks
                    match handled with
                    | Error e, _ -> return Error e
                    | Ok (), Some (SshError.Disconnected _) -> return Ok !ctx
                    | Ok (), _ -> return! loop ()
        }

        return! loop ()
    }
    let runMessageLoopRef stream ctx locks channelCallbacks =
        runMessageLoopWithTimeout stream ctx locks channelCallbacks None


    let runMessageLoop
        (stream: NetworkStream)
        (ctx: SessionContext)
        (_authCallbacks: AuthCallbacks)
        (channelCallbacks: ChannelCallbacks) = async {
        let locks = SessionLocks.create ()
        let ctxRef = ref ctx
        return! runMessageLoopRef stream ctxRef locks channelCallbacks
    }

    let private runSessionCore
        (stream: NetworkStream)
        (config: ServerConfig)
        (authCallbacks: AuthCallbacks)
        (channelFactory: ChannelCallbackFactory)
        (deadline: CancellationTokenSource) = async {
        let ctx = create config.ServerVersion

        let! versionResult = Transport.exchangeVersions stream config.ServerVersion
        match versionResult with
        | Error e -> return Error e
        | Ok clientVersion ->
            let ctxWithVersion = {
                ctx with
                    TransportState = { ctx.TransportState with ClientVersion = Some clientVersion }
                    State = KeyExchange
            }

            let! kexResult = KeyExchange.handleKeyExchange stream ctxWithVersion.TransportState config.HostKeys
            match kexResult with
            | Error e -> return Error e
            | Ok (transportAfterKex, kexState, _) ->
                let ctxAfterKex = {
                    ctxWithVersion with
                        TransportState = transportAfterKex
                        KexState = kexState
                        State = Authenticating
                }

                match kexState.SessionId with
                | None -> return Error (ProtocolError "No session ID after key exchange")
                | Some sessionId ->
                    let! authResult =
                        Auth.runAuthLoop
                            stream
                            ctxAfterKex.TransportState
                            sessionId
                            authCallbacks
                            config.MaxAuthAttempts

                    match authResult with
                    | Error e -> return Error e
                    | Ok (transportAfterAuth, authState) ->
                        let locks = SessionLocks.create ()
                        let ctxRef = ref {
                            ctxAfterKex with
                                TransportState = transportAfterAuth
                                AuthState = Some authState
                                State = Authenticated
                                Username = authState.Username
                        }
                        let channelCallbacks = channelFactory stream ctxRef locks authState
                        deadline.CancelAfter(config.IdleTimeout)
                        return! runMessageLoopWithTimeout stream ctxRef locks channelCallbacks (Some (deadline, config.IdleTimeout))
    }

    /// Enforce the authentication deadline from version exchange and the idle
    /// deadline after authentication, including time spent in callbacks.
    let runSessionWithFactory
        (stream: NetworkStream)
        (config: ServerConfig)
        (authCallbacks: AuthCallbacks)
        (channelFactory: ChannelCallbackFactory) = async {
        let! cancellation = Async.CancellationToken
        use deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation)
        use registration = deadline.Token.Register(fun () -> stream.Dispose())
        deadline.CancelAfter(config.AuthTimeout)
        return!
            task {
                try
                    return! Async.StartAsTask(
                        runSessionCore stream config authCallbacks channelFactory deadline,
                        cancellationToken = deadline.Token)
                with :? OperationCanceledException ->
                    return Error (ConnectionError "Session timed out or was cancelled")
            } |> Async.AwaitTask
    }

    let runSession
        (stream: NetworkStream)
        (config: ServerConfig)
        (authCallbacks: AuthCallbacks)
        (channelCallbacks: ChannelCallbacks) = async {
        return!
            runSessionWithFactory
                stream
                config
                authCallbacks
                (fun _ _ _ _ -> channelCallbacks)
    }

    let sendDisconnect
        (stream: NetworkStream)
        (ctx: SessionContext)
        (reason: uint32)
        (description: string) = async {

        let disconnectMsg = Disconnect(reason, description, "")
        let! sent = Transport.sendMessage stream ctx.TransportState disconnectMsg
        match sent with
        | Ok transport -> return { ctx with TransportState = transport; State = SessionState.Disconnected }
        | Error _ -> return { ctx with State = SessionState.Disconnected }
    }

    let sendData
        (stream: NetworkStream)
        (ctx: SessionContext)
        (channelId: uint32)
        (data: byte[]) = async {
        let mutable state = ctx.TransportState
        let mutable position = 0
        let mutable failure : SshResult<unit> option = None
        while failure.IsNone && position < data.Length do
            match Channel.acquireOutboundCredit ctx.ChannelManager channelId data position with
            | Error e -> failure <- Some (Error e)
            | Ok (Channel.Waiting signal) ->
                match! Channel.waitForCredit signal CancellationToken.None with
                | Error e -> failure <- Some (Error e)
                | Ok () -> ()
            | Ok (Channel.Granted chunk) ->
                match Channel.ChannelManager.getChannel ctx.ChannelManager channelId with
                | None -> failure <- Some (Error (ChannelError $"Unknown channel: {channelId}"))
                | Some channel ->
                    let! result =
                        Transport.sendMessage stream state (ChannelData(channel.RemoteChannel, chunk))
                    match result with
                    | Error e -> failure <- Some (Error e)
                    | Ok newTransport ->
                        state <- newTransport
                        position <- position + chunk.Length
        match failure with
        | Some result -> return result, ctx
        | None -> return Ok (), { ctx with TransportState = state }
    }

    let closeChannelWithStatus
        (stream: NetworkStream)
        (ctx: SessionContext)
        (channelId: uint32)
        (exitStatus: uint32) = async {

        let! statusResult = Channel.sendExitStatus stream ctx.TransportState ctx.ChannelManager channelId exitStatus
        match statusResult with
        | Error e -> return Error e, ctx
        | Ok stateAfterStatus ->
            let! eofResult = Channel.sendChannelEof stream stateAfterStatus ctx.ChannelManager channelId
            match eofResult with
            | Error e -> return Error e, { ctx with TransportState = stateAfterStatus }
            | Ok stateAfterEof ->
                let! closeResult = Channel.closeChannel stream stateAfterEof ctx.ChannelManager channelId
                match closeResult with
                | Error e -> return Error e, { ctx with TransportState = stateAfterEof }
                | Ok stateAfterClose -> return Ok (), { ctx with TransportState = stateAfterClose }
    }
