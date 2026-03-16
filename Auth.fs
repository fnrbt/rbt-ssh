namespace Ssh

open System
open System.Net.Sockets

module Auth =

    type AuthState = {
        Username: string option
        ServiceName: string option
        AuthAttempts: int
        MaxAttempts: int
        SessionId: byte[]
        AvailableMethods: string list
    }

    module AuthState =
        let create sessionId maxAttempts = {
            Username = None
            ServiceName = None
            AuthAttempts = 0
            MaxAttempts = maxAttempts
            SessionId = sessionId
            AvailableMethods = ["publickey"; "password"]
        }

    // Build the data that is signed for public key authentication
    // Format: session_id || SSH_MSG_USERAUTH_REQUEST packet data
    let buildPublicKeySignatureData
        (sessionId: byte[])
        (userName: string)
        (serviceName: string)
        (algorithmName: string)
        (publicKeyBlob: byte[]) =

        Array.concat [|
            Packet.writeBytes sessionId
            [| MessageTypes.SSH_MSG_USERAUTH_REQUEST |]
            Packet.writeString userName
            Packet.writeString serviceName
            Packet.writeString "publickey"
            Packet.writeBool true
            Packet.writeString algorithmName
            Packet.writeBytes publicKeyBlob
        |]

    // Handle SSH_MSG_USERAUTH_REQUEST
    let handleAuthRequest
        (stream: NetworkStream)
        (transportState: TransportState)
        (authState: AuthState)
        (authCallbacks: AuthCallbacks)
        (msg: SshMessage) = async {

        match msg with
        | UserAuthRequest(userName, serviceName, methodName, methodData) ->
            let newAuthState = {
                authState with
                    Username = Some userName
                    ServiceName = Some serviceName
                    AuthAttempts = authState.AuthAttempts + 1
            }

            if newAuthState.AuthAttempts > newAuthState.MaxAttempts then
                // Too many attempts, disconnect
                let disconnectMsg = Disconnect(
                    DisconnectReason.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
                    "Too many authentication attempts",
                    ""
                )
                let! _ = Transport.sendMessage stream transportState disconnectMsg
                return Error (AuthenticationError "Too many authentication attempts")
            else
                match methodName, methodData with
                | "none", _ ->
                    // "none" method always fails but returns available methods
                    let failureMsg = UserAuthFailure(newAuthState.AvailableMethods, false)
                    let! sendResult = Transport.sendMessage stream transportState failureMsg
                    match sendResult with
                    | Error e -> return Error e
                    | Ok newTransportState ->
                        return Ok (newTransportState, newAuthState, false)

                | "password", Password(password) ->
                    // Validate password via callback
                    let! authResult = authCallbacks.ValidatePassword userName password
                    match authResult with
                    | Accepted ->
                        let successMsg = UserAuthSuccess
                        let! sendResult = Transport.sendMessage stream transportState successMsg
                        match sendResult with
                        | Error e -> return Error e
                        | Ok newTransportState ->
                            return Ok (newTransportState, newAuthState, true)

                    | Rejected ->
                        let failureMsg = UserAuthFailure(newAuthState.AvailableMethods, false)
                        let! sendResult = Transport.sendMessage stream transportState failureMsg
                        match sendResult with
                        | Error e -> return Error e
                        | Ok newTransportState ->
                            return Ok (newTransportState, newAuthState, false)

                    | PartialSuccess remainingMethods ->
                        let failureMsg = UserAuthFailure(remainingMethods, true)
                        let! sendResult = Transport.sendMessage stream transportState failureMsg
                        match sendResult with
                        | Error e -> return Error e
                        | Ok newTransportState ->
                            return Ok (newTransportState, { newAuthState with AvailableMethods = remainingMethods }, false)

                | "publickey", PublicKey(algorithmName, publicKeyBlob, signatureOpt) ->
                    match signatureOpt with
                    | None ->
                        // Query: check if public key is acceptable
                        let! authResult = authCallbacks.ValidatePublicKey userName algorithmName publicKeyBlob
                        match authResult with
                        | Accepted | PartialSuccess _ ->
                            // Send PK_OK to indicate the key is acceptable
                            let pkOkMsg = UserAuthPkOk(algorithmName, publicKeyBlob)
                            let! sendResult = Transport.sendMessage stream transportState pkOkMsg
                            match sendResult with
                            | Error e -> return Error e
                            | Ok newTransportState ->
                                return Ok (newTransportState, newAuthState, false)

                        | Rejected ->
                            let failureMsg = UserAuthFailure(newAuthState.AvailableMethods, false)
                            let! sendResult = Transport.sendMessage stream transportState failureMsg
                            match sendResult with
                            | Error e -> return Error e
                            | Ok newTransportState ->
                                return Ok (newTransportState, newAuthState, false)

                    | Some signature ->
                        // Full authentication with signature
                        // First verify the public key is acceptable
                        let! authResult = authCallbacks.ValidatePublicKey userName algorithmName publicKeyBlob
                        match authResult with
                        | Rejected ->
                            let failureMsg = UserAuthFailure(newAuthState.AvailableMethods, false)
                            let! sendResult = Transport.sendMessage stream transportState failureMsg
                            match sendResult with
                            | Error e -> return Error e
                            | Ok newTransportState ->
                                return Ok (newTransportState, newAuthState, false)

                        | Accepted | PartialSuccess _ ->
                            // Verify the signature
                            let signatureData = buildPublicKeySignatureData
                                                    newAuthState.SessionId
                                                    userName
                                                    serviceName
                                                    algorithmName
                                                    publicKeyBlob

                            let signatureValid = Crypto.verifyPublicKeySignature publicKeyBlob signature signatureData

                            if signatureValid then
                                match authResult with
                                | Accepted ->
                                    let successMsg = UserAuthSuccess
                                    let! sendResult = Transport.sendMessage stream transportState successMsg
                                    match sendResult with
                                    | Error e -> return Error e
                                    | Ok newTransportState ->
                                        return Ok (newTransportState, newAuthState, true)

                                | PartialSuccess remainingMethods ->
                                    let failureMsg = UserAuthFailure(remainingMethods, true)
                                    let! sendResult = Transport.sendMessage stream transportState failureMsg
                                    match sendResult with
                                    | Error e -> return Error e
                                    | Ok newTransportState ->
                                        return Ok (newTransportState, { newAuthState with AvailableMethods = remainingMethods }, false)

                                | Rejected ->
                                    // Already handled above
                                    return Error (AuthenticationError "Unexpected state")
                            else
                                let failureMsg = UserAuthFailure(newAuthState.AvailableMethods, false)
                                let! sendResult = Transport.sendMessage stream transportState failureMsg
                                match sendResult with
                                | Error e -> return Error e
                                | Ok newTransportState ->
                                    return Ok (newTransportState, newAuthState, false)

                | _ ->
                    // Unknown or unsupported method
                    let failureMsg = UserAuthFailure(newAuthState.AvailableMethods, false)
                    let! sendResult = Transport.sendMessage stream transportState failureMsg
                    match sendResult with
                    | Error e -> return Error e
                    | Ok newTransportState ->
                        return Ok (newTransportState, newAuthState, false)

        | _ ->
            return Error (ProtocolError "Expected USERAUTH_REQUEST")
    }

    // Handle service request (usually "ssh-userauth")
    let handleServiceRequest
        (stream: NetworkStream)
        (transportState: TransportState)
        (msg: SshMessage) = async {

        match msg with
        | ServiceRequest(serviceName) ->
            if serviceName = "ssh-userauth" then
                let acceptMsg = ServiceAccept(serviceName)
                let! sendResult = Transport.sendMessage stream transportState acceptMsg
                match sendResult with
                | Error e -> return Error e
                | Ok newTransportState ->
                    return Ok (newTransportState, serviceName)
            else
                return Error (ProtocolError $"Unsupported service: {serviceName}")
        | _ ->
            return Error (ProtocolError "Expected SERVICE_REQUEST")
    }

    // Run authentication loop
    let runAuthLoop
        (stream: NetworkStream)
        (transportState: TransportState)
        (sessionId: byte[])
        (authCallbacks: AuthCallbacks)
        (maxAttempts: int) = async {

        // First, handle SERVICE_REQUEST
        let! serviceResult = Transport.receiveMessage stream transportState
        match serviceResult with
        | Error e -> return Error e
        | Ok (serviceMsg, stateAfterService) ->
            let! handleResult = handleServiceRequest stream stateAfterService serviceMsg
            match handleResult with
            | Error e -> return Error e
            | Ok (stateAfterAccept, _serviceName) ->
                // Now handle authentication requests
                let authState = AuthState.create sessionId maxAttempts

                let rec authLoop currentTransportState currentAuthState = async {
                    let! recvResult = Transport.receiveMessage stream currentTransportState
                    match recvResult with
                    | Error e -> return Error e
                    | Ok (authMsg, stateAfterRecv) ->
                        let! authResult = handleAuthRequest stream stateAfterRecv currentAuthState authCallbacks authMsg
                        match authResult with
                        | Error e -> return Error e
                        | Ok (newTransportState, newAuthState, authenticated) ->
                            if authenticated then
                                return Ok (newTransportState, newAuthState)
                            else
                                return! authLoop newTransportState newAuthState
                }

                return! authLoop stateAfterAccept authState
    }
