namespace Ssh

open System
open System.IO
open System.Net.Sockets
open System.Text

type TransportState = {
    ClientVersion: string option
    ServerVersion: string
    EncryptionEnabled: bool
    ClientToServerSequence: uint32
    ServerToClientSequence: uint32
    Keys: DerivedKeys option
    ClientToServerIV: byte[] option
    ServerToClientIV: byte[] option
    Role: ConnectionRole
}

module TransportState =
    let create serverVersion = {
        ClientVersion = None
        ServerVersion = serverVersion
        EncryptionEnabled = false
        ClientToServerSequence = 0u
        ServerToClientSequence = 0u
        Keys = None
        ClientToServerIV = None
        ServerToClientIV = None
        Role = Server
    }

    let createClient clientVersion = {
        ClientVersion = Some clientVersion
        ServerVersion = ""
        EncryptionEnabled = false
        ClientToServerSequence = 0u
        ServerToClientSequence = 0u
        Keys = None
        ClientToServerIV = None
        ServerToClientIV = None
        Role = Client
    }

module Transport =

    // Role-aware key selection: which keys to use for reading vs writing
    // Server reads client-to-server, writes server-to-client
    // Client reads server-to-client, writes client-to-server
    let private getReadKeys (state: TransportState) =
        match state.Role, state.Keys with
        | Server, Some keys -> Some (state.ClientToServerSequence, state.ClientToServerIV, keys.ClientToServerEncryptionKey, keys.ClientToServerMacKey)
        | Client, Some keys -> Some (state.ServerToClientSequence, state.ServerToClientIV, keys.ServerToClientEncryptionKey, keys.ServerToClientMacKey)
        | _, _ -> None

    let private updateReadState (state: TransportState) (newSeq: uint32) (newIv: byte[] option) =
        match state.Role with
        | Server -> { state with ClientToServerSequence = newSeq; ClientToServerIV = newIv |> Option.orElse state.ClientToServerIV }
        | Client -> { state with ServerToClientSequence = newSeq; ServerToClientIV = newIv |> Option.orElse state.ServerToClientIV }

    let private getWriteKeys (state: TransportState) =
        match state.Role, state.Keys with
        | Server, Some keys -> Some (state.ServerToClientSequence, state.ServerToClientIV, keys.ServerToClientEncryptionKey, keys.ServerToClientMacKey)
        | Client, Some keys -> Some (state.ClientToServerSequence, state.ClientToServerIV, keys.ClientToServerEncryptionKey, keys.ClientToServerMacKey)
        | _, _ -> None

    let private updateWriteState (state: TransportState) (newSeq: uint32) (newIv: byte[] option) =
        match state.Role with
        | Server -> { state with ServerToClientSequence = newSeq; ServerToClientIV = newIv |> Option.orElse state.ServerToClientIV }
        | Client -> { state with ClientToServerSequence = newSeq; ClientToServerIV = newIv |> Option.orElse state.ClientToServerIV }

    let private readLineAsync (stream: NetworkStream) = async {
        let buffer = ResizeArray<byte>()
        let singleByte = Array.zeroCreate<byte> 1

        let rec readLoop () = async {
            let! bytesRead = stream.ReadAsync(singleByte, 0, 1) |> Async.AwaitTask
            if bytesRead = 0 then
                return None
            else
                let b = singleByte.[0]
                if b = 10uy then  // \n
                    // Remove trailing \r if present
                    if buffer.Count > 0 && buffer.[buffer.Count - 1] = 13uy then
                        buffer.RemoveAt(buffer.Count - 1)
                    return Some (Encoding.ASCII.GetString(buffer.ToArray()))
                else
                    buffer.Add(b)
                    if buffer.Count > 255 then
                        return None  // Line too long
                    else
                        return! readLoop ()
        }

        return! readLoop ()
    }

    let private readSshVersion (stream: NetworkStream) = async {
        let rec readVersion () = async {
            let! lineOpt = readLineAsync stream
            match lineOpt with
            | None -> return Error (ProtocolError "Failed to read SSH version")
            | Some line ->
                if line.StartsWith("SSH-") then
                    if line.StartsWith("SSH-2.0-") || line.StartsWith("SSH-1.99-") then
                        return Ok line
                    else
                        return Error (ProtocolError $"Unsupported SSH version: {line}")
                else
                    return! readVersion ()
        }
        return! readVersion ()
    }

    let private sendVersion (stream: NetworkStream) (version: string) = async {
        let versionLine = version + "\r\n"
        let versionBytes = Encoding.ASCII.GetBytes(versionLine)
        do! stream.WriteAsync(versionBytes, 0, versionBytes.Length) |> Async.AwaitTask
    }

    /// Server-side version exchange: send server version, read client version
    let exchangeVersions (stream: NetworkStream) (serverVersion: string) = async {
        do! sendVersion stream serverVersion
        return! readSshVersion stream
    }

    /// Client-side version exchange: read server version, send client version
    let exchangeVersionsAsClient (stream: NetworkStream) (clientVersion: string) = async {
        let! serverVersionResult = readSshVersion stream
        match serverVersionResult with
        | Error e -> return Error e
        | Ok serverVersion ->
            do! sendVersion stream clientVersion
            return Ok serverVersion
    }

    let private readExactAsync (stream: NetworkStream) (count: int) = async {
        let buffer = Array.zeroCreate<byte> count
        let mutable totalRead = 0
        while totalRead < count do
            let! bytesRead = stream.ReadAsync(buffer, totalRead, count - totalRead) |> Async.AwaitTask
            if bytesRead = 0 then
                failwith "Connection closed"
            totalRead <- totalRead + bytesRead
        return buffer
    }

    let readPacket (stream: NetworkStream) (state: TransportState) = async {
        if not state.EncryptionEnabled then
            // Unencrypted packet
            let! lengthBytes = readExactAsync stream 4
            let packetLength = int (Packet.readUint32 lengthBytes 0)

            if packetLength < 1 || packetLength > int Constants.MaxPacketSize then
                return Error (ProtocolError $"Invalid packet length: {packetLength}")
            else
                let! packetData = readExactAsync stream packetLength
                let paddingLength = int packetData.[0]
                let payloadLength = packetLength - paddingLength - 1

                if payloadLength < 0 || paddingLength < 4 then
                    return Error (ProtocolError "Invalid packet structure")
                else
                    let payload = packetData.[1..payloadLength]
                    let readSeq =
                        match state.Role with
                        | Server -> state.ClientToServerSequence
                        | Client -> state.ServerToClientSequence
                    let newState = updateReadState state (readSeq + 1u) None
                    return Ok (payload, newState)
        else
            match getReadKeys state with
            | Some (readSeq, Some iv, encKey, macKey) ->
                // Encrypted packet
                let blockSize = Constants.BlockSize
                let! firstBlock = readExactAsync stream blockSize
                let decryptedFirstBlock = Crypto.aes256CtrDecrypt encKey iv firstBlock

                // Update IV for next block
                let newIv = Array.copy iv
                let mutable carry = 1
                for i = blockSize - 1 downto 0 do
                    if carry > 0 then
                        let sum = int newIv.[i] + carry
                        newIv.[i] <- byte (sum &&& 0xFF)
                        carry <- sum >>> 8

                let packetLength = int (Packet.readUint32 decryptedFirstBlock 0)

                if packetLength < 1 || packetLength > int Constants.MaxPacketSize then
                    return Error (ProtocolError $"Invalid encrypted packet length: {packetLength}")
                else
                    let totalEncryptedLength = 4 + packetLength
                    let remainingEncrypted = totalEncryptedLength - blockSize
                    let blocksRemaining = (remainingEncrypted + blockSize - 1) / blockSize

                    let! remainingData = readExactAsync stream (blocksRemaining * blockSize)
                    let! mac = readExactAsync stream Constants.MacLength

                    // Decrypt remaining data
                    let mutable currentIv = newIv
                    let decryptedRemaining = Array.zeroCreate<byte> remainingData.Length

                    for i in 0 .. blocksRemaining - 1 do
                        let blockStart = i * blockSize
                        let block = remainingData.[blockStart..blockStart + blockSize - 1]
                        let decryptedBlock = Crypto.aes256CtrDecrypt encKey currentIv block
                        Array.Copy(decryptedBlock, 0, decryptedRemaining, blockStart, blockSize)

                        let mutable c = 1
                        for j = blockSize - 1 downto 0 do
                            if c > 0 then
                                let sum = int currentIv.[j] + c
                                currentIv.[j] <- byte (sum &&& 0xFF)
                                c <- sum >>> 8

                    let fullDecrypted = Array.append decryptedFirstBlock decryptedRemaining
                    let actualPacketData = fullDecrypted.[0..4 + packetLength - 1]

                    // Verify MAC
                    let seqBytes = Packet.writeUint32 readSeq
                    let macInput = Array.append seqBytes actualPacketData

                    if not (Crypto.verifyHmacSha256 macKey macInput mac) then
                        return Error (ProtocolError "MAC verification failed")
                    else
                        let paddingLength = int fullDecrypted.[4]
                        let payloadLength = packetLength - paddingLength - 1
                        let payload = fullDecrypted.[5..5 + payloadLength - 1]
                        let newState = updateReadState state (readSeq + 1u) (Some currentIv)
                        return Ok (payload, newState)
            | _ ->
                return Error (ProtocolError "Encryption enabled but no keys available")
    }

    let writePacket (stream: NetworkStream) (state: TransportState) (payload: byte[]) = async {
        if not state.EncryptionEnabled then
            let packet = Packet.buildPacket payload 8
            do! stream.WriteAsync(packet, 0, packet.Length) |> Async.AwaitTask
            let writeSeq =
                match state.Role with
                | Server -> state.ServerToClientSequence
                | Client -> state.ClientToServerSequence
            return Ok (updateWriteState state (writeSeq + 1u) None)
        else
            match getWriteKeys state with
            | Some (writeSeq, Some iv, encKey, macKey) ->
                let blockSize = Constants.BlockSize
                let packet = Packet.buildPacket payload blockSize

                // SSH uses encrypt-and-MAC: MAC(seq || unencrypted_packet)
                let seqBytes = Packet.writeUint32 writeSeq
                let macInput = Array.append seqBytes packet
                let mac = Crypto.hmacSha256 macKey macInput

                let encrypted = Crypto.aes256CtrEncrypt encKey iv packet

                // Calculate new IV after encrypting all blocks
                let numBlocks = (packet.Length + blockSize - 1) / blockSize
                let mutable newIv = Array.copy iv
                for _ in 1 .. numBlocks do
                    let mutable carry = 1
                    for j = blockSize - 1 downto 0 do
                        if carry > 0 then
                            let sum = int newIv.[j] + carry
                            newIv.[j] <- byte (sum &&& 0xFF)
                            carry <- sum >>> 8

                let output = Array.append encrypted mac
                do! stream.WriteAsync(output, 0, output.Length) |> Async.AwaitTask

                return Ok (updateWriteState state (writeSeq + 1u) (Some newIv))
            | _ ->
                return Error (ProtocolError "Encryption enabled but no keys available")
    }

    let sendMessage (stream: NetworkStream) (state: TransportState) (msg: SshMessage) = async {
        let payload = Packet.buildMessagePayload msg
        return! writePacket stream state payload
    }

    let receiveMessage (stream: NetworkStream) (state: TransportState) = async {
        let! result = readPacket stream state
        match result with
        | Ok (payload, newState) ->
            let msg = Packet.parseMessage payload
            return Ok (msg, newState)
        | Error e ->
            return Error e
    }

    let enableEncryption (state: TransportState) (keys: DerivedKeys) =
        {
            state with
                EncryptionEnabled = true
                Keys = Some keys
                ClientToServerIV = Some keys.ClientToServerIV
                ServerToClientIV = Some keys.ServerToClientIV
        }
