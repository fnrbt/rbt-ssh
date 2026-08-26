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

type ChannelCallbackFactory =
    NetworkStream -> SessionContext ref -> SemaphoreSlim -> Auth.AuthState -> ChannelCallbacks

module Session =

    let create serverVersion = {
        TransportState = TransportState.create serverVersion
        KexState = KexState.empty
        ChannelManager = Channel.ChannelManager.create()
        AuthState = None
        State = VersionExchange
        Username = None
    }

    let private withSendLock (sendLock: SemaphoreSlim) work = async {
        do! sendLock.WaitAsync() |> Async.AwaitTask
        try
            return! work()
        finally
            sendLock.Release() |> ignore
    }

    let private sendMessageRef
        (stream: NetworkStream)
        (ctx: SessionContext ref)
        (sendLock: SemaphoreSlim)
        (message: SshMessage) = async {
        return!
            withSendLock sendLock (fun () -> async {
                let current = !ctx
                let! sent = Transport.sendMessage stream current.TransportState message
                match sent with
                | Error e -> return Error e
                | Ok transport ->
                    ctx := { !ctx with TransportState = transport }
                    return Ok ()
            })
    }

    let sendDataRef
        (stream: NetworkStream)
        (ctx: SessionContext ref)
        (sendLock: SemaphoreSlim)
        (channelId: uint32)
        (data: byte[]) = async {
        return!
            withSendLock sendLock (fun () -> async {
                let current = !ctx
                let! result = Channel.sendChannelData stream current.TransportState current.ChannelManager channelId data
                match result with
                | Error e -> return Error e
                | Ok transport ->
                    ctx := { !ctx with TransportState = transport }
                    return Ok ()
            })
    }

    let sendExtendedDataRef
        (stream: NetworkStream)
        (ctx: SessionContext ref)
        (sendLock: SemaphoreSlim)
        (channelId: uint32)
        (dataTypeCode: uint32)
        (data: byte[]) = async {
        return!
            withSendLock sendLock (fun () -> async {
                let current = !ctx
                let! result = Channel.sendChannelExtendedData stream current.TransportState current.ChannelManager channelId dataTypeCode data
                match result with
                | Error e -> return Error e
                | Ok transport ->
                    ctx := { !ctx with TransportState = transport }
                    return Ok ()
            })
    }

    let closeChannelWithStatusRef
        (stream: NetworkStream)
        (ctx: SessionContext ref)
        (sendLock: SemaphoreSlim)
        (channelId: uint32)
        (exitStatus: uint32) = async {
        return!
            withSendLock sendLock (fun () -> async {
                let current = !ctx
                let! statusResult = Channel.sendExitStatus stream current.TransportState current.ChannelManager channelId exitStatus
                match statusResult with
                | Error e -> return Error e
                | Ok stateAfterStatus ->
                    let! eofResult = Channel.sendChannelEof stream stateAfterStatus current.ChannelManager channelId
                    match eofResult with
                    | Error e ->
                        ctx := { !ctx with TransportState = stateAfterStatus }
                        return Error e
                    | Ok stateAfterEof ->
                        let! closeResult = Channel.closeChannel stream stateAfterEof current.ChannelManager channelId
                        match closeResult with
                        | Error e ->
                            ctx := { !ctx with TransportState = stateAfterEof }
                            return Error e
                        | Ok stateAfterClose ->
                            ctx := { !ctx with TransportState = stateAfterClose }
                            return Ok ()
            })
    }

    let private handleMessageRef
        (stream: NetworkStream)
        (ctx: SessionContext ref)
        (sendLock: SemaphoreSlim)
        (msg: SshMessage)
        (channelCallbacks: ChannelCallbacks) = async {

        match msg with
        | Disconnect(reason, description, _) ->
            ctx := { !ctx with State = SessionState.Disconnected }
            return Ok (), Some (SshError.Disconnected(reason, description))

        | Ignore _ | Unimplemented _ | Debug _ ->
            return Ok (), None

        | GlobalRequest(_, wantReply, _) ->
            if wantReply then
                let! sent = sendMessageRef stream ctx sendLock RequestFailure
                return sent, None
            else
                return Ok (), None

        | ChannelOpen(channelType, senderChannel, initialWindowSize, maximumPacketSize, data) ->
            let! result =
                withSendLock sendLock (fun () -> async {
                    let current = !ctx
                    return!
                        Channel.handleChannelOpen
                            stream current.TransportState current.ChannelManager
                            channelType senderChannel initialWindowSize maximumPacketSize data
                })
            match result with
            | Error e -> return Error e, None
            | Ok (transport, manager, _) ->
                ctx := { !ctx with TransportState = transport; ChannelManager = manager }
                return Ok (), None

        | ChannelRequest(recipientChannel, requestType, wantReply, data) ->
            let current = !ctx
            let! result =
                Channel.handleChannelRequest
                    stream current.TransportState current.ChannelManager
                    channelCallbacks recipientChannel requestType wantReply data
            match result with
            | Error e -> return Error e, None
            | Ok (_, manager, success, replyChannelOpt) ->
                ctx := { !ctx with ChannelManager = manager }
                match replyChannelOpt with
                | Some remoteChannel ->
                    let reply = if success then ChannelSuccess(remoteChannel) else ChannelFailure(remoteChannel)
                    let! sent = sendMessageRef stream ctx sendLock reply
                    return sent, None
                | None ->
                    return Ok (), None

        | ChannelData(recipientChannel, data) ->
            let current = !ctx
            let! result = Channel.handleChannelData current.ChannelManager channelCallbacks recipientChannel data
            match result with
            | Error e -> return Error e, None
            | Ok manager ->
                ctx := { !ctx with ChannelManager = manager }
                let! adjustResult =
                    withSendLock sendLock (fun () -> async {
                        let latest = !ctx
                        return!
                            Channel.sendWindowAdjust
                                stream
                                latest.TransportState
                                latest.ChannelManager
                                recipientChannel
                                (uint32 data.Length)
                    })
                match adjustResult with
                | Error e -> return Error e, None
                | Ok transport ->
                    ctx := { !ctx with TransportState = transport }
                    return Ok (), None

        | ChannelExtendedData(recipientChannel, dataTypeCode, data) ->
            let current = !ctx
            let! result = Channel.handleChannelExtendedData current.ChannelManager channelCallbacks recipientChannel dataTypeCode data
            match result with
            | Error e -> return Error e, None
            | Ok manager ->
                ctx := { !ctx with ChannelManager = manager }
                return Ok (), None

        | ChannelEof(recipientChannel) ->
            let current = !ctx
            let! result = Channel.handleChannelEof current.ChannelManager channelCallbacks recipientChannel
            match result with
            | Error e -> return Error e, None
            | Ok manager ->
                ctx := { !ctx with ChannelManager = manager }
                return Ok (), None

        | ChannelClose(recipientChannel) ->
            let! result =
                withSendLock sendLock (fun () -> async {
                    let current = !ctx
                    return! Channel.handleChannelClose stream current.TransportState current.ChannelManager channelCallbacks recipientChannel
                })
            match result with
            | Error e -> return Error e, None
            | Ok (transport, manager) ->
                ctx := { !ctx with TransportState = transport; ChannelManager = manager }
                return Ok (), None

        | ChannelWindowAdjust(recipientChannel, bytesToAdd) ->
            let current = !ctx
            match Channel.handleWindowAdjust current.ChannelManager recipientChannel bytesToAdd with
            | Error e -> return Error e, None
            | Ok manager ->
                ctx := { !ctx with ChannelManager = manager }
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
            let! sent = sendMessageRef stream ctx sendLock (Unimplemented sequence)
            return sent, None
    }

    let runMessageLoopRef
        (stream: NetworkStream)
        (ctx: SessionContext ref)
        (sendLock: SemaphoreSlim)
        (channelCallbacks: ChannelCallbacks) = async {

        let rec loop () = async {
            let current = !ctx
            if current.State = SessionState.Disconnected then
                return Ok current
            else
                let! received = Transport.receiveMessage stream current.TransportState
                match received with
                | Error e -> return Error e
                | Ok (msg, transportAfterReceive) ->
                    let latest = !ctx
                    ctx := {
                        latest with
                            TransportState = {
                                transportAfterReceive with
                                    ServerToClientSequence = latest.TransportState.ServerToClientSequence
                                    ServerToClientIV = latest.TransportState.ServerToClientIV
                            }
                    }
                    let! handled = handleMessageRef stream ctx sendLock msg channelCallbacks
                    match handled with
                    | Error e, _ -> return Error e
                    | Ok (), Some (SshError.Disconnected _) -> return Ok !ctx
                    | Ok (), _ -> return! loop ()
        }

        return! loop ()
    }

    let runMessageLoop
        (stream: NetworkStream)
        (ctx: SessionContext)
        (_authCallbacks: AuthCallbacks)
        (channelCallbacks: ChannelCallbacks) = async {
        use sendLock = new SemaphoreSlim(1, 1)
        let ctxRef = ref ctx
        return! runMessageLoopRef stream ctxRef sendLock channelCallbacks
    }

    let runSessionWithFactory
        (stream: NetworkStream)
        (config: ServerConfig)
        (authCallbacks: AuthCallbacks)
        (channelFactory: ChannelCallbackFactory) = async {

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
                        use sendLock = new SemaphoreSlim(1, 1)
                        let ctxRef = ref {
                            ctxAfterKex with
                                TransportState = transportAfterAuth
                                AuthState = Some authState
                                State = Authenticated
                                Username = authState.Username
                        }
                        let channelCallbacks = channelFactory stream ctxRef sendLock authState
                        return! runMessageLoopRef stream ctxRef sendLock channelCallbacks
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
        let! result = Channel.sendChannelData stream ctx.TransportState ctx.ChannelManager channelId data
        match result with
        | Error e -> return Error e, ctx
        | Ok transport -> return Ok (), { ctx with TransportState = transport }
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
