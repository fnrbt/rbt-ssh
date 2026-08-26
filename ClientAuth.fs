namespace Rbt.Ssh

open System.Net.Sockets

module ClientAuth =

    type ClientAuthMethod =
        | PasswordAuth of password: string
        | PublicKeyAuth of key: HostKey

    type ClientAuthConfig = {
        Username: string
        Methods: ClientAuthMethod list
    }

    /// Send SERVICE_REQUEST and wait for SERVICE_ACCEPT
    let private requestService
        (stream: NetworkStream)
        (transportState: TransportState)
        (serviceName: string) = async {

        let! sendResult = Transport.sendMessage stream transportState (ServiceRequest(serviceName))
        match sendResult with
        | Error e -> return Error e
        | Ok stateAfterSend ->
            let! recvResult = Transport.receiveMessage stream stateAfterSend
            match recvResult with
            | Error e -> return Error e
            | Ok (msg, stateAfterRecv) ->
                match msg with
                | ServiceAccept(name) when name = serviceName ->
                    return Ok stateAfterRecv
                | _ ->
                    return Error (ProtocolError $"Expected SERVICE_ACCEPT for {serviceName}")
    }

    /// Try password authentication
    let private tryPassword
        (stream: NetworkStream)
        (transportState: TransportState)
        (username: string)
        (password: string) = async {

        let authMsg = UserAuthRequest(username, "ssh-connection", "password", Password(password))
        let! sendResult = Transport.sendMessage stream transportState authMsg
        match sendResult with
        | Error e -> return Error e
        | Ok stateAfterSend ->
            return Ok stateAfterSend
    }

    /// Try public key authentication (query + sign)
    let private tryPublicKey
        (stream: NetworkStream)
        (transportState: TransportState)
        (sessionId: byte[])
        (username: string)
        (hostKey: HostKey) = async {

        let algorithmName =
            match hostKey.KeyType with
            | Ed25519 -> Algorithms.HOSTKEY_SSH_ED25519
            | Rsa -> Algorithms.HOSTKEY_RSA_SHA2_256

        // First, send query (no signature) to check if key is acceptable
        let queryMsg = UserAuthRequest(
            username, "ssh-connection", "publickey",
            PublicKey(algorithmName, hostKey.PublicKeyBlob, None))
        let! sendResult = Transport.sendMessage stream transportState queryMsg
        match sendResult with
        | Error e -> return Error e
        | Ok stateAfterQuery ->
            let! recvResult = Transport.receiveMessage stream stateAfterQuery
            match recvResult with
            | Error e -> return Error e
            | Ok (msg, stateAfterRecv) ->
                match msg with
                | UserAuthPkOk(_algName, _keyBlob) ->
                    // Key is acceptable, sign and send full request
                    let signatureData = Auth.buildPublicKeySignatureData
                                            sessionId username "ssh-connection"
                                            algorithmName hostKey.PublicKeyBlob
                    let signature = Crypto.signWithHostKey hostKey signatureData (Some algorithmName)
                    let authMsg = UserAuthRequest(
                        username, "ssh-connection", "publickey",
                        PublicKey(algorithmName, hostKey.PublicKeyBlob, Some signature))
                    let! sendResult2 = Transport.sendMessage stream stateAfterRecv authMsg
                    match sendResult2 with
                    | Error e -> return Error e
                    | Ok stateAfterAuth ->
                        return Ok stateAfterAuth
                | UserAuthFailure _ ->
                    // Key not accepted, return state so caller can try next method
                    return Ok stateAfterRecv
                | UserAuthSuccess ->
                    // Some servers accept on query alone (unlikely but handle it)
                    return Ok stateAfterRecv
                | _ ->
                    return Error (ProtocolError "Unexpected response to publickey query")
    }

    /// Drive authentication from the client side
    let authenticate
        (stream: NetworkStream)
        (transportState: TransportState)
        (sessionId: byte[])
        (config: ClientAuthConfig) = async {

        // Request ssh-userauth service
        let! serviceResult = requestService stream transportState "ssh-userauth"
        match serviceResult with
        | Error e -> return Error e
        | Ok stateAfterService ->
            // Try each method in order
            let rec tryMethods (state: TransportState) (methods: ClientAuthMethod list) = async {
                match methods with
                | [] ->
                    return Error (AuthenticationError "All authentication methods exhausted")
                | method :: remaining ->
                    let! stateAfterAttempt = async {
                        match method with
                        | PasswordAuth password ->
                            return! tryPassword stream state config.Username password
                        | PublicKeyAuth key ->
                            return! tryPublicKey stream state sessionId config.Username key
                    }
                    match stateAfterAttempt with
                    | Error e -> return Error e
                    | Ok newState ->
                        // Read response (may already have been read for pubkey query)
                        let! recvResult = Transport.receiveMessage stream newState
                        match recvResult with
                        | Error e -> return Error e
                        | Ok (msg, stateAfterRecv) ->
                            match msg with
                            | UserAuthSuccess ->
                                return Ok stateAfterRecv
                            | UserAuthFailure(_availableMethods, _partialSuccess) ->
                                return! tryMethods stateAfterRecv remaining
                            | UserAuthBanner(_message, _) ->
                                // Banner can appear before success/failure, read again
                                let! recvResult2 = Transport.receiveMessage stream stateAfterRecv
                                match recvResult2 with
                                | Error e -> return Error e
                                | Ok (msg2, stateAfterRecv2) ->
                                    match msg2 with
                                    | UserAuthSuccess ->
                                        return Ok stateAfterRecv2
                                    | UserAuthFailure _ ->
                                        return! tryMethods stateAfterRecv2 remaining
                                    | _ ->
                                        return Error (ProtocolError "Unexpected message during auth")
                            | _ ->
                                return Error (ProtocolError "Unexpected message during auth")
            }

            return! tryMethods stateAfterService config.Methods
    }
