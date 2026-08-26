namespace Rbt.Ssh

open System.Net.Sockets

module ClientKeyExchange =

    /// Create client KEXINIT message (same algorithm set as server)
    let createClientKexInit () =
        let cookie = Crypto.randomBytes 16
        KexInit(
            cookie,
            [ Algorithms.KEX_CURVE25519_SHA256; Algorithms.KEX_CURVE25519_SHA256_LIBSSH ],
            [ Algorithms.HOSTKEY_SSH_ED25519; Algorithms.HOSTKEY_RSA_SHA2_256; Algorithms.HOSTKEY_RSA_SHA2_512 ],
            [ Algorithms.CIPHER_AES256_CTR ], [ Algorithms.CIPHER_AES256_CTR ],
            [ Algorithms.MAC_HMAC_SHA2_256 ], [ Algorithms.MAC_HMAC_SHA2_256 ],
            [ Algorithms.COMPRESSION_NONE ], [ Algorithms.COMPRESSION_NONE ],
            [], [],
            false
        )

    /// Verify host key against verification policy
    let verifyHostKey (verification: HostKeyVerification) (hostKeyBlob: byte[]) =
        match verification with
        | AcceptAll -> true
        | Fingerprint expectedFingerprints ->
            let hash = Crypto.sha256 hostKeyBlob
            let fingerprint =
                "SHA256:" + System.Convert.ToBase64String(hash).TrimEnd('=')
            expectedFingerprints |> List.exists (fun fp -> fp = fingerprint)
        | Custom verify ->
            // Extract algorithm name from blob for the callback
            match Crypto.parsePublicKeyBlob hostKeyBlob with
            | Some (algName, _) -> verify algName hostKeyBlob
            | None -> false

    /// Client-side ECDH key exchange
    let performKeyExchange
        (stream: NetworkStream)
        (transportState: TransportState)
        (kexState: KexState)
        (hostKeyVerification: HostKeyVerification) = async {

        // Generate client ephemeral key pair
        let (clientEphemeralPublic, clientEphemeralPrivate) = Crypto.generateCurve25519KeyPair()

        // Send KEX_ECDH_INIT
        let initMsg = KexEcdhInit(clientEphemeralPublic)
        let! sendResult = Transport.sendMessage stream transportState initMsg
        match sendResult with
        | Error e -> return Error e
        | Ok stateAfterInit ->
            // Receive KEX_ECDH_REPLY
            let! recvResult = Transport.receiveMessage stream stateAfterInit
            match recvResult with
            | Error e -> return Error e
            | Ok (msg, stateAfterReply) ->
                match msg with
                | KexEcdhReply(hostKeyBlob, serverEphemeralPublic, signature) ->
                    // Verify host key
                    if not (verifyHostKey hostKeyVerification hostKeyBlob) then
                        return Error (CryptoError "Host key verification failed")
                    else
                        // Compute shared secret
                        match Crypto.computeCurve25519SharedSecret clientEphemeralPrivate serverEphemeralPublic with
                        | None ->
                            return Error (CryptoError "Failed to compute shared secret")
                        | Some sharedSecret ->
                            // Compute exchange hash
                            match kexState.ClientKexInit, kexState.ServerKexInit, stateAfterReply.ClientVersion with
                            | Some clientKexPayload, Some serverKexPayload, Some clientVersion ->
                                let exchangeHash = KeyExchange.computeExchangeHash
                                                    clientVersion
                                                    stateAfterReply.ServerVersion
                                                    clientKexPayload
                                                    serverKexPayload
                                                    hostKeyBlob
                                                    clientEphemeralPublic
                                                    serverEphemeralPublic
                                                    sharedSecret

                                // Verify the server's signature over the exchange hash
                                if not (Crypto.verifyPublicKeySignature hostKeyBlob signature exchangeHash) then
                                    return Error (CryptoError "Exchange hash signature verification failed")
                                else
                                    let sessionId =
                                        match kexState.SessionId with
                                        | Some sid -> sid
                                        | None -> exchangeHash

                                    // Send NEWKEYS
                                    let! newKeysResult = Transport.sendMessage stream stateAfterReply NewKeys
                                    match newKeysResult with
                                    | Error e -> return Error e
                                    | Ok stateAfterNewKeys ->
                                        // Receive server's NEWKEYS
                                        let! serverNewKeysResult = Transport.receiveMessage stream stateAfterNewKeys
                                        match serverNewKeysResult with
                                        | Error e -> return Error e
                                        | Ok (serverMsg, stateAfterServerNewKeys) ->
                                            match serverMsg with
                                            | NewKeys ->
                                                let derivedKeys = Crypto.deriveAllKeys sharedSecret exchangeHash sessionId
                                                let encryptedState = Transport.enableEncryption stateAfterServerNewKeys derivedKeys

                                                let newKexState = {
                                                    kexState with
                                                        ClientEphemeralPublic = Some clientEphemeralPublic
                                                        ServerEphemeralPublic = Some serverEphemeralPublic
                                                        SharedSecret = Some sharedSecret
                                                        ExchangeHash = Some exchangeHash
                                                        SessionId = Some sessionId
                                                }

                                                return Ok (encryptedState, newKexState, derivedKeys)
                                            | _ ->
                                                return Error (ProtocolError "Expected NEWKEYS from server")
                            | _ ->
                                return Error (ProtocolError "Missing KEXINIT payloads or client version")
                | _ ->
                    return Error (ProtocolError "Expected KEX_ECDH_REPLY")
    }

    /// Handle full client-side key exchange
    let handleKeyExchange
        (stream: NetworkStream)
        (transportState: TransportState)
        (hostKeyVerification: HostKeyVerification) = async {

        // Send client KEXINIT
        let clientKexInit = createClientKexInit()
        let clientKexPayload = Packet.buildMessagePayload clientKexInit

        let! sendResult = Transport.sendMessage stream transportState clientKexInit
        match sendResult with
        | Error e -> return Error e
        | Ok stateAfterKexInit ->
            // Receive server KEXINIT
            let! recvResult = Transport.receiveMessage stream stateAfterKexInit
            match recvResult with
            | Error e -> return Error e
            | Ok (serverMsg, stateAfterServerKexInit) ->
                match serverMsg with
                | KexInit _ as serverKexInit ->
                    let serverKexPayload = Packet.buildMessagePayload serverKexInit

                    // Negotiate algorithms (client's list is checked first per RFC 4253)
                    match KeyExchange.negotiateAlgorithms clientKexInit serverKexInit with
                    | Error e -> return Error e
                    | Ok (kexAlg, _hostKeyAlg, _, _, _, _, _, _) ->
                        if kexAlg <> Algorithms.KEX_CURVE25519_SHA256 &&
                           kexAlg <> Algorithms.KEX_CURVE25519_SHA256_LIBSSH then
                            return Error (ProtocolError $"Unsupported KEX algorithm: {kexAlg}")
                        else
                            let kexState = {
                                KexState.empty with
                                    ClientKexInit = Some clientKexPayload
                                    ServerKexInit = Some serverKexPayload
                            }
                            return! performKeyExchange stream stateAfterServerKexInit kexState hostKeyVerification
                | _ ->
                    return Error (ProtocolError "Expected KEXINIT from server")
    }
