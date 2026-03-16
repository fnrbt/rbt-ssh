namespace Ssh

open System
open System.IO
open System.Text

module Packet =

    // Read a uint32 from a byte array at offset (big-endian)
    let readUint32 (data: byte[]) (offset: int) =
        let bytes = data.[offset..offset+3]
        if BitConverter.IsLittleEndian then
            Array.Reverse(bytes)
        BitConverter.ToUInt32(ReadOnlySpan(bytes))

    // Read a byte from a byte array at offset
    let readByte (data: byte[]) (offset: int) =
        data.[offset]

    // Read an SSH string (uint32 length + data)
    let readString (data: byte[]) (offset: int) =
        let length = int (readUint32 data offset)
        let str = Encoding.UTF8.GetString(data, offset + 4, length)
        (str, offset + 4 + length)

    // Read raw bytes with length prefix
    let readBytes (data: byte[]) (offset: int) =
        let length = int (readUint32 data offset)
        let bytes = data.[offset + 4 .. offset + 4 + length - 1]
        (bytes, offset + 4 + length)

    // Read a boolean
    let readBool (data: byte[]) (offset: int) =
        (data.[offset] <> 0uy, offset + 1)

    // Read a name-list (comma-separated strings)
    let readNameList (data: byte[]) (offset: int) =
        let (str, newOffset) = readString data offset
        let names =
            if String.IsNullOrEmpty(str) then []
            else str.Split(',') |> Array.toList
        (names, newOffset)

    // Read an mpint (SSH multiprecision integer)
    let readMpint (data: byte[]) (offset: int) =
        let length = int (readUint32 data offset)
        if length = 0 then
            ([| 0uy |], offset + 4)
        else
            let bytes = data.[offset + 4 .. offset + 4 + length - 1]
            (bytes, offset + 4 + length)

    // Write a uint32 to big-endian bytes
    let writeUint32 (value: uint32) =
        let bytes = BitConverter.GetBytes(value)
        if BitConverter.IsLittleEndian then
            Array.Reverse(bytes)
        bytes

    // Write an SSH string
    let writeString (str: string) =
        let bytes = Encoding.UTF8.GetBytes(str)
        Array.append (writeUint32 (uint32 bytes.Length)) bytes

    // Write raw bytes with length prefix
    let writeBytes (data: byte[]) =
        Array.append (writeUint32 (uint32 data.Length)) data

    // Write a boolean
    let writeBool (value: bool) =
        [| if value then 1uy else 0uy |]

    // Write a name-list
    let writeNameList (names: string list) =
        writeString (String.concat "," names)

    // Write an mpint
    let writeMpint (value: byte[]) =
        // Remove leading zeros
        let mutable startIdx = 0
        while startIdx < value.Length - 1 && value.[startIdx] = 0uy do
            startIdx <- startIdx + 1
        let trimmed = value.[startIdx..]
        // Add leading zero if MSB is set (to ensure positive)
        let needsPadding = trimmed.Length > 0 && (trimmed.[0] &&& 0x80uy) <> 0uy
        let mpint = if needsPadding then Array.append [| 0uy |] trimmed else trimmed
        Array.append (writeUint32 (uint32 mpint.Length)) mpint

    // Build an unencrypted SSH packet
    // Format: uint32 packet_length || byte padding_length || payload || padding || MAC (added later)
    let buildPacket (payload: byte[]) (blockSize: int) =
        // RFC 4253: The total length of (packet_length || padding_length || payload || padding)
        // must be a multiple of the cipher block size or 8, whichever is larger.
        // packet_length field itself (4 bytes) is included in alignment calculation.
        // Padding must be 4-255 bytes.
        let minPadding = 4

        // Total packet on wire = 4 (packet_length) + 1 (padding_length) + payload + padding
        // This total must be a multiple of blockSize
        let baseSize = 4 + 1 + payload.Length + minPadding
        let remainder = baseSize % blockSize
        let paddingLength =
            if remainder = 0 then minPadding
            else minPadding + (blockSize - remainder)

        // Ensure minimum packet size of 16 bytes (including packet_length field)
        let paddingLength =
            if 4 + 1 + payload.Length + paddingLength < 16 then
                paddingLength + blockSize
            else
                paddingLength

        let packetLength = 1 + payload.Length + paddingLength
        let padding = Crypto.randomBytes paddingLength

        Array.concat [|
            writeUint32 (uint32 packetLength)
            [| byte paddingLength |]
            payload
            padding
        |]

    // Parse an SSH message from payload
    let parseMessage (payload: byte[]) : SshMessage =
        if payload.Length < 1 then
            RawMessage(0uy, [||])
        else
            let msgType = payload.[0]
            let data = payload.[1..]

            match msgType with
            | MessageTypes.SSH_MSG_DISCONNECT ->
                let reason = readUint32 data 0
                let (description, offset1) = readString data 4
                let (language, _) = readString data offset1
                Disconnect(reason, description, language)

            | MessageTypes.SSH_MSG_IGNORE ->
                let (ignoreData, _) = readBytes data 0
                Ignore(ignoreData)

            | MessageTypes.SSH_MSG_UNIMPLEMENTED ->
                let seqNum = readUint32 data 0
                Unimplemented(seqNum)

            | MessageTypes.SSH_MSG_DEBUG ->
                let (alwaysDisplay, offset1) = readBool data 0
                let (message, offset2) = readString data offset1
                let (language, _) = readString data offset2
                Debug(alwaysDisplay, message, language)

            | MessageTypes.SSH_MSG_SERVICE_REQUEST ->
                let (serviceName, _) = readString data 0
                ServiceRequest(serviceName)

            | MessageTypes.SSH_MSG_SERVICE_ACCEPT ->
                let (serviceName, _) = readString data 0
                ServiceAccept(serviceName)

            | MessageTypes.SSH_MSG_KEXINIT ->
                let cookie = data.[0..15]
                let (kexAlgorithms, offset1) = readNameList data 16
                let (serverHostKeyAlgorithms, offset2) = readNameList data offset1
                let (encryptionClientToServer, offset3) = readNameList data offset2
                let (encryptionServerToClient, offset4) = readNameList data offset3
                let (macClientToServer, offset5) = readNameList data offset4
                let (macServerToClient, offset6) = readNameList data offset5
                let (compressionClientToServer, offset7) = readNameList data offset6
                let (compressionServerToClient, offset8) = readNameList data offset7
                let (languagesClientToServer, offset9) = readNameList data offset8
                let (languagesServerToClient, offset10) = readNameList data offset9
                let (firstKexPacketFollows, _) = readBool data offset10
                KexInit(cookie, kexAlgorithms, serverHostKeyAlgorithms,
                        encryptionClientToServer, encryptionServerToClient,
                        macClientToServer, macServerToClient,
                        compressionClientToServer, compressionServerToClient,
                        languagesClientToServer, languagesServerToClient,
                        firstKexPacketFollows)

            | MessageTypes.SSH_MSG_NEWKEYS ->
                NewKeys

            | MessageTypes.SSH_MSG_KEX_ECDH_INIT ->
                let (clientPublicKey, _) = readBytes data 0
                KexEcdhInit(clientPublicKey)

            | MessageTypes.SSH_MSG_KEX_ECDH_REPLY ->
                let (hostKey, offset1) = readBytes data 0
                let (serverPublicKey, offset2) = readBytes data offset1
                let (signature, _) = readBytes data offset2
                KexEcdhReply(hostKey, serverPublicKey, signature)

            | MessageTypes.SSH_MSG_USERAUTH_REQUEST ->
                let (userName, offset1) = readString data 0
                let (serviceName, offset2) = readString data offset1
                let (methodName, offset3) = readString data offset2
                let methodData =
                    match methodName with
                    | "none" -> AuthMethodData.NoAuth
                    | "password" ->
                        let (_falseFlag, offset4) = readBool data offset3
                        let (password, _) = readString data offset4
                        Password(password)
                    | "publickey" ->
                        let (hasSignature, offset4) = readBool data offset3
                        let (algorithmName, offset5) = readString data offset4
                        let (publicKeyBlob, offset6) = readBytes data offset5
                        if hasSignature then
                            let (signature, _) = readBytes data offset6
                            PublicKey(algorithmName, publicKeyBlob, Some signature)
                        else
                            PublicKey(algorithmName, publicKeyBlob, None)
                    | _ -> AuthMethodData.NoAuth
                UserAuthRequest(userName, serviceName, methodName, methodData)

            | MessageTypes.SSH_MSG_USERAUTH_FAILURE ->
                let (authMethods, offset1) = readNameList data 0
                let (partialSuccess, _) = readBool data offset1
                UserAuthFailure(authMethods, partialSuccess)

            | MessageTypes.SSH_MSG_USERAUTH_SUCCESS ->
                UserAuthSuccess

            | MessageTypes.SSH_MSG_USERAUTH_BANNER ->
                let (message, offset1) = readString data 0
                let (language, _) = readString data offset1
                UserAuthBanner(message, language)

            | MessageTypes.SSH_MSG_USERAUTH_PK_OK ->
                let (algorithmName, offset1) = readString data 0
                let (publicKeyBlob, _) = readBytes data offset1
                UserAuthPkOk(algorithmName, publicKeyBlob)

            | MessageTypes.SSH_MSG_GLOBAL_REQUEST ->
                let (requestName, offset1) = readString data 0
                let (wantReply, offset2) = readBool data offset1
                let requestData = data.[offset2..]
                GlobalRequest(requestName, wantReply, requestData)

            | MessageTypes.SSH_MSG_REQUEST_SUCCESS ->
                RequestSuccess(data)

            | MessageTypes.SSH_MSG_REQUEST_FAILURE ->
                RequestFailure

            | MessageTypes.SSH_MSG_CHANNEL_OPEN ->
                let (channelType, offset1) = readString data 0
                let senderChannel = readUint32 data offset1
                let initialWindowSize = readUint32 data (offset1 + 4)
                let maximumPacketSize = readUint32 data (offset1 + 8)
                let channelData = data.[offset1 + 12..]
                ChannelOpen(channelType, senderChannel, initialWindowSize, maximumPacketSize, channelData)

            | MessageTypes.SSH_MSG_CHANNEL_OPEN_CONFIRMATION ->
                let recipientChannel = readUint32 data 0
                let senderChannel = readUint32 data 4
                let initialWindowSize = readUint32 data 8
                let maximumPacketSize = readUint32 data 12
                let channelData = data.[16..]
                ChannelOpenConfirmation(recipientChannel, senderChannel, initialWindowSize, maximumPacketSize, channelData)

            | MessageTypes.SSH_MSG_CHANNEL_OPEN_FAILURE ->
                let recipientChannel = readUint32 data 0
                let reasonCode = readUint32 data 4
                let (description, offset1) = readString data 8
                let (language, _) = readString data offset1
                ChannelOpenFailure(recipientChannel, reasonCode, description, language)

            | MessageTypes.SSH_MSG_CHANNEL_WINDOW_ADJUST ->
                let recipientChannel = readUint32 data 0
                let bytesToAdd = readUint32 data 4
                ChannelWindowAdjust(recipientChannel, bytesToAdd)

            | MessageTypes.SSH_MSG_CHANNEL_DATA ->
                let recipientChannel = readUint32 data 0
                let (channelData, _) = readBytes data 4
                ChannelData(recipientChannel, channelData)

            | MessageTypes.SSH_MSG_CHANNEL_EXTENDED_DATA ->
                let recipientChannel = readUint32 data 0
                let dataTypeCode = readUint32 data 4
                let (channelData, _) = readBytes data 8
                ChannelExtendedData(recipientChannel, dataTypeCode, channelData)

            | MessageTypes.SSH_MSG_CHANNEL_EOF ->
                let recipientChannel = readUint32 data 0
                ChannelEof(recipientChannel)

            | MessageTypes.SSH_MSG_CHANNEL_CLOSE ->
                let recipientChannel = readUint32 data 0
                ChannelClose(recipientChannel)

            | MessageTypes.SSH_MSG_CHANNEL_REQUEST ->
                let recipientChannel = readUint32 data 0
                let (requestType, offset1) = readString data 4
                let (wantReply, offset2) = readBool data offset1
                let requestData = data.[offset2..]
                ChannelRequest(recipientChannel, requestType, wantReply, requestData)

            | MessageTypes.SSH_MSG_CHANNEL_SUCCESS ->
                let recipientChannel = readUint32 data 0
                ChannelSuccess(recipientChannel)

            | MessageTypes.SSH_MSG_CHANNEL_FAILURE ->
                let recipientChannel = readUint32 data 0
                ChannelFailure(recipientChannel)

            | _ ->
                RawMessage(msgType, data)

    // Build message payload from SshMessage
    let buildMessagePayload (msg: SshMessage) : byte[] =
        match msg with
        | Disconnect(reason, description, language) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_DISCONNECT |]
                writeUint32 reason
                writeString description
                writeString language
            |]

        | Ignore(data) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_IGNORE |]
                writeBytes data
            |]

        | Unimplemented(seqNum) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_UNIMPLEMENTED |]
                writeUint32 seqNum
            |]

        | Debug(alwaysDisplay, message, language) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_DEBUG |]
                writeBool alwaysDisplay
                writeString message
                writeString language
            |]

        | ServiceRequest(serviceName) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_SERVICE_REQUEST |]
                writeString serviceName
            |]

        | ServiceAccept(serviceName) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_SERVICE_ACCEPT |]
                writeString serviceName
            |]

        | KexInit(cookie, kexAlgorithms, serverHostKeyAlgorithms,
                  encryptionClientToServer, encryptionServerToClient,
                  macClientToServer, macServerToClient,
                  compressionClientToServer, compressionServerToClient,
                  languagesClientToServer, languagesServerToClient,
                  firstKexPacketFollows) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_KEXINIT |]
                cookie
                writeNameList kexAlgorithms
                writeNameList serverHostKeyAlgorithms
                writeNameList encryptionClientToServer
                writeNameList encryptionServerToClient
                writeNameList macClientToServer
                writeNameList macServerToClient
                writeNameList compressionClientToServer
                writeNameList compressionServerToClient
                writeNameList languagesClientToServer
                writeNameList languagesServerToClient
                writeBool firstKexPacketFollows
                writeUint32 0u  // reserved
            |]

        | NewKeys ->
            [| MessageTypes.SSH_MSG_NEWKEYS |]

        | KexEcdhInit(clientPublicKey) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_KEX_ECDH_INIT |]
                writeBytes clientPublicKey
            |]

        | KexEcdhReply(hostKey, serverPublicKey, signature) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_KEX_ECDH_REPLY |]
                writeBytes hostKey
                writeBytes serverPublicKey
                writeBytes signature
            |]

        | UserAuthRequest(userName, serviceName, methodName, methodData) ->
            let methodPayload =
                match methodData with
                | AuthMethodData.NoAuth -> [||]
                | Password(password) ->
                    Array.concat [| writeBool false; writeString password |]
                | PublicKey(algorithmName, publicKeyBlob, signature) ->
                    match signature with
                    | Some sigBytes ->
                        Array.concat [|
                            writeBool true
                            writeString algorithmName
                            writeBytes publicKeyBlob
                            writeBytes sigBytes
                        |]
                    | None ->
                        Array.concat [|
                            writeBool false
                            writeString algorithmName
                            writeBytes publicKeyBlob
                        |]
                | HostBased(algorithmName, publicKeyBlob, clientHostName, clientUserName, signature) ->
                    Array.concat [|
                        writeString algorithmName
                        writeBytes publicKeyBlob
                        writeString clientHostName
                        writeString clientUserName
                        writeBytes signature
                    |]
            Array.concat [|
                [| MessageTypes.SSH_MSG_USERAUTH_REQUEST |]
                writeString userName
                writeString serviceName
                writeString methodName
                methodPayload
            |]

        | UserAuthFailure(authMethods, partialSuccess) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_USERAUTH_FAILURE |]
                writeNameList authMethods
                writeBool partialSuccess
            |]

        | UserAuthSuccess ->
            [| MessageTypes.SSH_MSG_USERAUTH_SUCCESS |]

        | UserAuthBanner(message, language) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_USERAUTH_BANNER |]
                writeString message
                writeString language
            |]

        | UserAuthPkOk(algorithmName, publicKeyBlob) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_USERAUTH_PK_OK |]
                writeString algorithmName
                writeBytes publicKeyBlob
            |]

        | GlobalRequest(requestName, wantReply, data) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_GLOBAL_REQUEST |]
                writeString requestName
                writeBool wantReply
                data
            |]

        | RequestSuccess(data) ->
            Array.append [| MessageTypes.SSH_MSG_REQUEST_SUCCESS |] data

        | RequestFailure ->
            [| MessageTypes.SSH_MSG_REQUEST_FAILURE |]

        | ChannelOpen(channelType, senderChannel, initialWindowSize, maximumPacketSize, data) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_CHANNEL_OPEN |]
                writeString channelType
                writeUint32 senderChannel
                writeUint32 initialWindowSize
                writeUint32 maximumPacketSize
                data
            |]

        | ChannelOpenConfirmation(recipientChannel, senderChannel, initialWindowSize, maximumPacketSize, data) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_CHANNEL_OPEN_CONFIRMATION |]
                writeUint32 recipientChannel
                writeUint32 senderChannel
                writeUint32 initialWindowSize
                writeUint32 maximumPacketSize
                data
            |]

        | ChannelOpenFailure(recipientChannel, reasonCode, description, language) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_CHANNEL_OPEN_FAILURE |]
                writeUint32 recipientChannel
                writeUint32 reasonCode
                writeString description
                writeString language
            |]

        | ChannelWindowAdjust(recipientChannel, bytesToAdd) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_CHANNEL_WINDOW_ADJUST |]
                writeUint32 recipientChannel
                writeUint32 bytesToAdd
            |]

        | ChannelData(recipientChannel, data) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_CHANNEL_DATA |]
                writeUint32 recipientChannel
                writeBytes data
            |]

        | ChannelExtendedData(recipientChannel, dataTypeCode, data) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_CHANNEL_EXTENDED_DATA |]
                writeUint32 recipientChannel
                writeUint32 dataTypeCode
                writeBytes data
            |]

        | ChannelEof(recipientChannel) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_CHANNEL_EOF |]
                writeUint32 recipientChannel
            |]

        | ChannelClose(recipientChannel) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_CHANNEL_CLOSE |]
                writeUint32 recipientChannel
            |]

        | ChannelRequest(recipientChannel, requestType, wantReply, data) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_CHANNEL_REQUEST |]
                writeUint32 recipientChannel
                writeString requestType
                writeBool wantReply
                data
            |]

        | ChannelSuccess(recipientChannel) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_CHANNEL_SUCCESS |]
                writeUint32 recipientChannel
            |]

        | ChannelFailure(recipientChannel) ->
            Array.concat [|
                [| MessageTypes.SSH_MSG_CHANNEL_FAILURE |]
                writeUint32 recipientChannel
            |]

        | RawMessage(msgType, data) ->
            Array.append [| msgType |] data

    // Parse channel request data
    let parseChannelRequest (requestType: string) (data: byte[]) : ChannelRequestData =
        match requestType with
        | "pty-req" ->
            let (term, offset1) = readString data 0
            let widthChars = readUint32 data offset1
            let heightRows = readUint32 data (offset1 + 4)
            let widthPixels = readUint32 data (offset1 + 8)
            let heightPixels = readUint32 data (offset1 + 12)
            let (modes, _) = readBytes data (offset1 + 16)
            PtyReq(term, widthChars, heightRows, widthPixels, heightPixels, modes)

        | "shell" ->
            Shell

        | "exec" ->
            let (command, _) = readString data 0
            Exec(command)

        | "subsystem" ->
            let (name, _) = readString data 0
            Subsystem(name)

        | "window-change" ->
            let widthChars = readUint32 data 0
            let heightRows = readUint32 data 4
            let widthPixels = readUint32 data 8
            let heightPixels = readUint32 data 12
            WindowChange(widthChars, heightRows, widthPixels, heightPixels)

        | "signal" ->
            let (signalName, _) = readString data 0
            Signal(signalName)

        | "exit-status" ->
            let exitStatus = readUint32 data 0
            ExitStatus(exitStatus)

        | "exit-signal" ->
            let (signalName, offset1) = readString data 0
            let (coreDumped, offset2) = readBool data offset1
            let (errorMessage, offset3) = readString data offset2
            let (language, _) = readString data offset3
            ExitSignal(signalName, coreDumped, errorMessage, language)

        | _ ->
            Unknown(requestType, data)

    // Build channel request data payload
    let buildChannelRequestData (requestData: ChannelRequestData) : byte[] =
        match requestData with
        | PtyReq(term, widthChars, heightRows, widthPixels, heightPixels, modes) ->
            Array.concat [|
                writeString term
                writeUint32 widthChars
                writeUint32 heightRows
                writeUint32 widthPixels
                writeUint32 heightPixels
                writeBytes modes
            |]

        | Shell -> [||]

        | Exec(command) ->
            writeString command

        | Subsystem(name) ->
            writeString name

        | WindowChange(widthChars, heightRows, widthPixels, heightPixels) ->
            Array.concat [|
                writeUint32 widthChars
                writeUint32 heightRows
                writeUint32 widthPixels
                writeUint32 heightPixels
            |]

        | Signal(signalName) ->
            writeString signalName

        | ExitStatus(exitStatus) ->
            writeUint32 exitStatus

        | ExitSignal(signalName, coreDumped, errorMessage, language) ->
            Array.concat [|
                writeString signalName
                writeBool coreDumped
                writeString errorMessage
                writeString language
            |]

        | Unknown(_, data) ->
            data
