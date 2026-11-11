namespace Rbt.Ssh

open System
open System.Net.Sockets
open System.Text

module KeyExchange =

    // Create server KEXINIT message
    let createServerKexInit (hostKeyTypes: string list) =
        let cookie = Crypto.randomBytes 16

        // Use both curve25519 algorithm names for compatibility
        let kexAlgorithms = [
            Algorithms.KEX_CURVE25519_SHA256
            Algorithms.KEX_CURVE25519_SHA256_LIBSSH
        ]

        // Build host key algorithms from available keys
        let serverHostKeyAlgorithms =
            hostKeyTypes
            |> List.collect (fun kt ->
                match kt with
                | "ed25519" -> [ Algorithms.HOSTKEY_SSH_ED25519 ]
                | "rsa" -> [
                    Algorithms.HOSTKEY_RSA_SHA2_256
                    Algorithms.HOSTKEY_RSA_SHA2_512
                  ]
                | _ -> []
            )

        let encryption = [ Algorithms.CIPHER_AES256_CTR ]
        let mac = [ Algorithms.MAC_HMAC_SHA2_256 ]
        let compression = [ Algorithms.COMPRESSION_NONE ]

        KexInit(
            cookie,
            kexAlgorithms,
            serverHostKeyAlgorithms,
            encryption, encryption,
            mac, mac,
            compression, compression,
            [], [],  // No language preference
            false    // No first KEX packet follows
        )

    // Negotiate algorithm from client and server lists
    let negotiateAlgorithm (clientList: string list) (serverList: string list) =
        clientList |> List.tryFind (fun c -> serverList |> List.contains c)

    // Negotiate all algorithms
    let negotiateAlgorithms (clientKexInit: SshMessage) (serverKexInit: SshMessage) =
        match clientKexInit, serverKexInit with
        | KexInit(_, clientKex, clientHostKey, clientEncCS, clientEncSC, clientMacCS, clientMacSC, clientCompCS, clientCompSC, _, _, _),
          KexInit(_, serverKex, serverHostKey, serverEncCS, serverEncSC, serverMacCS, serverMacSC, serverCompCS, serverCompSC, _, _, _) ->

            let kex = negotiateAlgorithm clientKex serverKex
            let hostKey = negotiateAlgorithm clientHostKey serverHostKey
            let encCS = negotiateAlgorithm clientEncCS serverEncCS
            let encSC = negotiateAlgorithm clientEncSC serverEncSC
            let macCS = negotiateAlgorithm clientMacCS serverMacCS
            let macSC = negotiateAlgorithm clientMacSC serverMacSC
            let compCS = negotiateAlgorithm clientCompCS serverCompCS
            let compSC = negotiateAlgorithm clientCompSC serverCompSC

            match kex, hostKey, encCS, encSC, macCS, macSC, compCS, compSC with
            | Some k, Some hk, Some eCS, Some eSC, Some mCS, Some mSC, Some cCS, Some cSC ->
                Ok (k, hk, eCS, eSC, mCS, mSC, cCS, cSC)
            | _ ->
                Error (ProtocolError "Failed to negotiate algorithms")
        | _ ->
            Error (ProtocolError "Invalid KEXINIT messages")

    // Compute exchange hash H for curve25519-sha256
    // H = hash(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
    let computeExchangeHash
        (clientVersion: string)
        (serverVersion: string)
        (clientKexInitPayload: byte[])
        (serverKexInitPayload: byte[])
        (hostKeyBlob: byte[])
        (clientEphemeralPublic: byte[])
        (serverEphemeralPublic: byte[])
        (sharedSecret: byte[]) =

        let hashInput = Array.concat [|
            Packet.writeString clientVersion
            Packet.writeString serverVersion
            Packet.writeBytes clientKexInitPayload
            Packet.writeBytes serverKexInitPayload
            Packet.writeBytes hostKeyBlob
            Packet.writeBytes clientEphemeralPublic
            Packet.writeBytes serverEphemeralPublic
            Crypto.encodePositiveMpint sharedSecret
        |]

        Crypto.sha256 hashInput

    // Find appropriate host key for algorithm
    let findHostKey (hostKeys: HostKey list) (algorithmName: string) =
        hostKeys |> List.tryFind (fun hk ->
            match hk.KeyType, algorithmName with
            | HostKeyType.Ed25519, alg when alg = Algorithms.HOSTKEY_SSH_ED25519 -> true
            | HostKeyType.Rsa, alg when alg = Algorithms.HOSTKEY_RSA_SHA2_256
                                     || alg = Algorithms.HOSTKEY_RSA_SHA2_512 -> true
            | _ -> false
        )

    /// Whether a peer's optimistic KEX packet must be ignored (RFC 4253 section 7.1).
    let incorrectGuess message kexAlgorithm hostKeyAlgorithm =
        match message with
        | KexInit(_, kex, hostKeys, _, _, _, _, _, _, _, _, follows) ->
            follows && (List.tryHead kex <> Some kexAlgorithm || List.tryHead hostKeys <> Some hostKeyAlgorithm)
        | _ -> false

    // Perform curve25519-sha256 key exchange (server side)
    let performKeyExchange
        (stream: NetworkStream)
        (transportState: TransportState)
        (kexState: KexState)
        (hostKeys: HostKey list)
        (negotiatedHostKeyAlg: string) = async {

        // Receive KEX_ECDH_INIT from client
        let! result = Transport.receiveMessage stream transportState
        match result with
        | Error e -> return Error e
        | Ok (msg, newTransportState) ->
            match msg with
            | KexEcdhInit(clientEphemeralPublic) ->
                // Generate server ephemeral key pair
                let (serverEphemeralPublic, serverEphemeralPrivate) = Crypto.generateCurve25519KeyPair()

                // Compute shared secret
                match Crypto.computeCurve25519SharedSecret serverEphemeralPrivate clientEphemeralPublic with
                | None ->
                    return Error (CryptoError "Failed to compute shared secret")
                | Some sharedSecret ->
                    // Find host key
                    match findHostKey hostKeys negotiatedHostKeyAlg with
                    | None ->
                        return Error (ProtocolError $"No host key available for {negotiatedHostKeyAlg}")
                    | Some hostKey ->
                        // Compute exchange hash
                        match kexState.ClientKexInit, kexState.ServerKexInit, newTransportState.ClientVersion with
                        | Some clientKexPayload, Some serverKexPayload, Some clientVersion ->
                            let exchangeHash = computeExchangeHash
                                                clientVersion
                                                newTransportState.ServerVersion
                                                clientKexPayload
                                                serverKexPayload
                                                hostKey.PublicKeyBlob
                                                clientEphemeralPublic
                                                serverEphemeralPublic
                                                sharedSecret

                            // Session ID is the first exchange hash
                            let sessionId =
                                match kexState.SessionId with
                                | Some sid -> sid
                                | None -> exchangeHash

                            // Sign the exchange hash
                            let signature = Crypto.signWithHostKey hostKey exchangeHash (Some negotiatedHostKeyAlg)

                            // Send KEX_ECDH_REPLY
                            let replyMsg = KexEcdhReply(hostKey.PublicKeyBlob, serverEphemeralPublic, signature)
                            let! sendResult = Transport.sendMessage stream newTransportState replyMsg
                            match sendResult with
                            | Error e -> return Error e
                            | Ok stateAfterReply ->
                                // Send NEWKEYS
                                let! newKeysResult = Transport.sendMessage stream stateAfterReply NewKeys
                                match newKeysResult with
                                | Error e -> return Error e
                                | Ok stateAfterNewKeys ->
                                    // Wait for client's NEWKEYS
                                    let! clientNewKeysResult = Transport.receiveMessage stream stateAfterNewKeys
                                    match clientNewKeysResult with
                                    | Error e -> return Error e
                                    | Ok (clientMsg, stateAfterClientNewKeys) ->
                                        match clientMsg with
                                        | NewKeys ->
                                            // Derive keys
                                            let derivedKeys = Crypto.deriveAllKeys sharedSecret exchangeHash sessionId

                                            // Enable encryption
                                            let encryptedState = Transport.enableEncryption stateAfterClientNewKeys derivedKeys

                                            let newKexState = {
                                                kexState with
                                                    ClientEphemeralPublic = Some clientEphemeralPublic
                                                    ServerEphemeralPublic = Some serverEphemeralPublic
                                                    ServerEphemeralPrivate = Some serverEphemeralPrivate
                                                    SharedSecret = Some sharedSecret
                                                    ExchangeHash = Some exchangeHash
                                                    SessionId = Some sessionId
                                            }

                                            return Ok (encryptedState, newKexState, derivedKeys)
                                        | _ ->
                                            return Error (ProtocolError "Expected NEWKEYS from client")
                        | _ ->
                            return Error (ProtocolError "Missing KEXINIT payloads or client version")
            | _ ->
                return Error (ProtocolError "Expected KEX_ECDH_INIT")
    }

    // Handle initial key exchange
    let handleKeyExchange
        (stream: NetworkStream)
        (transportState: TransportState)
        (hostKeys: HostKey list) = async {

        // Create and send server KEXINIT
        let hostKeyTypes =
            hostKeys |> List.map (fun hk ->
                match hk.KeyType with
                | HostKeyType.Ed25519 -> "ed25519"
                | HostKeyType.Rsa -> "rsa"
            ) |> List.distinct

        let serverKexInit = createServerKexInit hostKeyTypes
        let serverKexPayload = Packet.buildMessagePayload serverKexInit

        let! sendResult = Transport.sendMessage stream transportState serverKexInit
        match sendResult with
        | Error e -> return Error e
        | Ok stateAfterKexInit ->
            // Receive client KEXINIT
            let! recvResult = Transport.receiveMessageWithPayload stream stateAfterKexInit
            match recvResult with
            | Error e -> return Error e
            | Ok (clientMsg, clientKexPayload, stateAfterClientKexInit) ->
                match clientMsg with
                | KexInit _ as clientKexInit ->
                    // Negotiate algorithms
                    match negotiateAlgorithms clientKexInit serverKexInit with
                    | Error e -> return Error e
                    | Ok (kexAlg, hostKeyAlg, _, _, _, _, _, _) ->
                        // Verify we support the negotiated KEX algorithm
                        if kexAlg <> Algorithms.KEX_CURVE25519_SHA256 &&
                           kexAlg <> Algorithms.KEX_CURVE25519_SHA256_LIBSSH then
                            return Error (ProtocolError $"Unsupported KEX algorithm: {kexAlg}")
                        else
                            let kexState = {
                                KexState.empty with
                                    ClientKexInit = Some clientKexPayload
                                    ServerKexInit = Some serverKexPayload
                            }

                            if incorrectGuess clientKexInit kexAlg hostKeyAlg then
                                let! ignored = Transport.readPacket stream stateAfterClientKexInit
                                match ignored with
                                | Error e -> return Error e
                                | Ok (_, stateAfterGuess) ->
                                    return! performKeyExchange stream stateAfterGuess kexState hostKeys hostKeyAlg
                            else
                                return! performKeyExchange stream stateAfterClientKexInit kexState hostKeys hostKeyAlg
                | _ ->
                    return Error (ProtocolError "Expected KEXINIT from client")
    }
