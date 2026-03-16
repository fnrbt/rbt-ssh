namespace Ssh

open System
open System.Net.Sockets

type SessionContext = {
    TransportState: TransportState
    KexState: KexState
    ChannelManager: Channel.ChannelManager
    AuthState: Auth.AuthState option
    State: SessionState
    Username: string option
}

module Session =

    let create serverVersion = {
        TransportState = TransportState.create serverVersion
        KexState = KexState.empty
        ChannelManager = Channel.ChannelManager.create()
        AuthState = None
        State = VersionExchange
        Username = None
    }

    // Handle a single message in the session
    let handleMessage
        (stream: NetworkStream)
        (ctx: SessionContext)
        (msg: SshMessage)
        (authCallbacks: AuthCallbacks)
        (channelCallbacks: ChannelCallbacks) = async {

        match msg with
        | Disconnect(reason, description, _) ->
            return Ok { ctx with State = SessionState.Disconnected }, Some (SshError.Disconnected(reason, description))

        | Ignore _ ->
            return Ok ctx, None

        | Unimplemented _ ->
            return Ok ctx, None

        | Debug(_, message, _) ->
            printfn "DEBUG: %s" message
            return Ok ctx, None

        | GlobalRequest(requestName, wantReply, _) ->
            if wantReply then
                let! sendResult = Transport.sendMessage stream ctx.TransportState RequestFailure
                match sendResult with
                | Error e -> return Error e, None
                | Ok newTransportState ->
                    return Ok { ctx with TransportState = newTransportState }, None
            else
                return Ok ctx, None

        | ChannelOpen(channelType, senderChannel, initialWindowSize, maximumPacketSize, data) ->
            let! result = Channel.handleChannelOpen
                            stream ctx.TransportState ctx.ChannelManager
                            channelType senderChannel initialWindowSize maximumPacketSize data
            match result with
            | Error e -> return Error e, None
            | Ok (newTransportState, newManager, _channelOpt) ->
                return Ok { ctx with TransportState = newTransportState; ChannelManager = newManager }, None

        | ChannelRequest(recipientChannel, requestType, wantReply, data) ->
            let! result = Channel.handleChannelRequest
                            stream ctx.TransportState ctx.ChannelManager channelCallbacks
                            recipientChannel requestType wantReply data
            match result with
            | Error e -> return Error e, None
            | Ok (_, newManager, success, replyChannelOpt) ->
                let mutable newCtx = { ctx with ChannelManager = newManager }
                // Send reply with current transport state
                match replyChannelOpt with
                | Some remoteChannel ->
                    let replyMsg = if success then ChannelSuccess(remoteChannel) else ChannelFailure(remoteChannel)
                    let! sendResult = Transport.sendMessage stream newCtx.TransportState replyMsg
                    match sendResult with
                    | Ok newTransport -> newCtx <- { newCtx with TransportState = newTransport }
                    | Error _ -> ()
                | None -> ()
                return Ok newCtx, None

        | ChannelData(recipientChannel, data) ->
            let! result = Channel.handleChannelData ctx.ChannelManager channelCallbacks recipientChannel data
            match result with
            | Error e -> return Error e, None
            | Ok newManager ->
                return Ok { ctx with ChannelManager = newManager }, None

        | ChannelExtendedData(recipientChannel, dataTypeCode, data) ->
            let! result = Channel.handleChannelExtendedData ctx.ChannelManager channelCallbacks recipientChannel dataTypeCode data
            match result with
            | Error e -> return Error e, None
            | Ok newManager ->
                return Ok { ctx with ChannelManager = newManager }, None

        | ChannelEof(recipientChannel) ->
            let! result = Channel.handleChannelEof ctx.ChannelManager channelCallbacks recipientChannel
            match result with
            | Error e -> return Error e, None
            | Ok newManager ->
                return Ok { ctx with ChannelManager = newManager }, None

        | ChannelClose(recipientChannel) ->
            let! result = Channel.handleChannelClose stream ctx.TransportState ctx.ChannelManager channelCallbacks recipientChannel
            match result with
            | Error e -> return Error e, None
            | Ok (newTransportState, newManager) ->
                return Ok { ctx with TransportState = newTransportState; ChannelManager = newManager }, None

        | ChannelWindowAdjust(recipientChannel, bytesToAdd) ->
            match Channel.handleWindowAdjust ctx.ChannelManager recipientChannel bytesToAdd with
            | Error e -> return Error e, None
            | Ok newManager ->
                return Ok { ctx with ChannelManager = newManager }, None

        | ChannelSuccess _ | ChannelFailure _ ->
            // These are responses to our requests, which we don't track currently
            return Ok ctx, None

        | UserAuthRequest _ ->
            // This shouldn't happen after authentication is complete
            if ctx.State = Authenticated then
                return Error (ProtocolError "Unexpected USERAUTH_REQUEST after authentication"), None
            else
                match ctx.AuthState with
                | None -> return Error (ProtocolError "Auth state not initialized"), None
                | Some authState ->
                    let! result = Auth.handleAuthRequest stream ctx.TransportState authState authCallbacks msg
                    match result with
                    | Error e -> return Error e, None
                    | Ok (newTransportState, newAuthState, authenticated) ->
                        if authenticated then
                            return Ok {
                                ctx with
                                    TransportState = newTransportState
                                    AuthState = Some newAuthState
                                    State = Authenticated
                                    Username = newAuthState.Username
                            }, None
                        else
                            return Ok {
                                ctx with
                                    TransportState = newTransportState
                                    AuthState = Some newAuthState
                            }, None

        | _ ->
            // Send unimplemented for unknown messages
            let unimplMsg = Unimplemented(ctx.TransportState.ClientToServerSequence - 1u)
            let! sendResult = Transport.sendMessage stream ctx.TransportState unimplMsg
            match sendResult with
            | Error e -> return Error e, None
            | Ok newTransportState ->
                return Ok { ctx with TransportState = newTransportState }, None
    }

    // Run the session message loop
    let runMessageLoop
        (stream: NetworkStream)
        (ctx: SessionContext)
        (authCallbacks: AuthCallbacks)
        (channelCallbacks: ChannelCallbacks) = async {

        let rec loop currentCtx = async {
            if currentCtx.State = SessionState.Disconnected then
                return Ok currentCtx
            else
                let! recvResult = Transport.receiveMessage stream currentCtx.TransportState
                match recvResult with
                | Error e ->
                    return Error e
                | Ok (msg, newTransportState) ->
                    let updatedCtx = { currentCtx with TransportState = newTransportState }
                    let! handleResult = handleMessage stream updatedCtx msg authCallbacks channelCallbacks
                    match handleResult with
                    | Error e, _ ->
                        return Error e
                    | Ok newCtx, Some (SshError.Disconnected _) ->
                        return Ok newCtx
                    | Ok newCtx, _ ->
                        return! loop newCtx
        }

        return! loop ctx
    }

    // Run a complete session from connection
    let runSession
        (stream: NetworkStream)
        (config: ServerConfig)
        (authCallbacks: AuthCallbacks)
        (channelCallbacks: ChannelCallbacks) = async {

        let ctx = create config.ServerVersion

        // Version exchange
        let! versionResult = Transport.exchangeVersions stream config.ServerVersion
        match versionResult with
        | Error e -> return Error e
        | Ok clientVersion ->
            let ctxWithVersion = {
                ctx with
                    TransportState = { ctx.TransportState with ClientVersion = Some clientVersion }
                    State = KeyExchange
            }

            // Key exchange
            let! kexResult = KeyExchange.handleKeyExchange stream ctxWithVersion.TransportState config.HostKeys
            match kexResult with
            | Error e -> return Error e
            | Ok (newTransportState, newKexState, _derivedKeys) ->
                let ctxAfterKex = {
                    ctxWithVersion with
                        TransportState = newTransportState
                        KexState = newKexState
                        State = Authenticating
                }

                // Authentication
                match newKexState.SessionId with
                | None -> return Error (ProtocolError "No session ID after key exchange")
                | Some sessionId ->
                    let! authResult = Auth.runAuthLoop
                                        stream
                                        ctxAfterKex.TransportState
                                        sessionId
                                        authCallbacks
                                        config.MaxAuthAttempts

                    match authResult with
                    | Error e -> return Error e
                    | Ok (transportAfterAuth, authState) ->
                        let ctxAuthenticated = {
                            ctxAfterKex with
                                TransportState = transportAfterAuth
                                AuthState = Some authState
                                State = Authenticated
                                Username = authState.Username
                        }

                        // Run main message loop
                        return! runMessageLoop stream ctxAuthenticated authCallbacks channelCallbacks
    }

    // Send disconnect message
    let sendDisconnect
        (stream: NetworkStream)
        (ctx: SessionContext)
        (reason: uint32)
        (description: string) = async {

        let disconnectMsg = Disconnect(reason, description, "")
        let! _ = Transport.sendMessage stream ctx.TransportState disconnectMsg
        return { ctx with State = SessionState.Disconnected }
    }

    // Send data to a channel
    let sendData
        (stream: NetworkStream)
        (ctx: SessionContext)
        (channelId: uint32)
        (data: byte[]) = async {

        let! result = Channel.sendChannelData stream ctx.TransportState ctx.ChannelManager channelId data
        match result with
        | Error e -> return Error e, ctx
        | Ok newTransportState ->
            return Ok (), { ctx with TransportState = newTransportState }
    }

    // Send exit status and close channel
    let closeChannelWithStatus
        (stream: NetworkStream)
        (ctx: SessionContext)
        (channelId: uint32)
        (exitStatus: uint32) = async {

        // Send exit status
        let! statusResult = Channel.sendExitStatus stream ctx.TransportState ctx.ChannelManager channelId exitStatus
        match statusResult with
        | Error e -> return Error e, ctx
        | Ok stateAfterStatus ->
            // Send EOF
            let! eofResult = Channel.sendChannelEof stream stateAfterStatus ctx.ChannelManager channelId
            match eofResult with
            | Error e -> return Error e, { ctx with TransportState = stateAfterStatus }
            | Ok stateAfterEof ->
                // Close channel
                let! closeResult = Channel.closeChannel stream stateAfterEof ctx.ChannelManager channelId
                match closeResult with
                | Error e -> return Error e, { ctx with TransportState = stateAfterEof }
                | Ok stateAfterClose ->
                    return Ok (), { ctx with TransportState = stateAfterClose }
    }
