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
    }

module Transport =

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

    let exchangeVersions (stream: NetworkStream) (serverVersion: string) = async {
        // Send server version
        let versionLine = serverVersion + "\r\n"
        let versionBytes = Encoding.ASCII.GetBytes(versionLine)
        do! stream.WriteAsync(versionBytes, 0, versionBytes.Length) |> Async.AwaitTask

        // Read client version (skip lines not starting with SSH-)
        let rec readClientVersion () = async {
            let! lineOpt = readLineAsync stream
            match lineOpt with
            | None -> return Error (ProtocolError "Failed to read client version")
            | Some line ->
                if line.StartsWith("SSH-") then
                    if line.StartsWith("SSH-2.0-") || line.StartsWith("SSH-1.99-") then
                        return Ok line
                    else
                        return Error (ProtocolError $"Unsupported SSH version: {line}")
                else
                    // Skip non-SSH lines (allowed before version)
                    return! readClientVersion ()
        }

        return! readClientVersion ()
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
                    let newState = { state with ClientToServerSequence = state.ClientToServerSequence + 1u }
                    return Ok (payload, newState)
        else
            match state.Keys, state.ClientToServerIV with
            | Some keys, Some iv ->
                // Encrypted packet
                // First, read and decrypt the first block to get packet length
                let blockSize = Constants.BlockSize
                let! firstBlock = readExactAsync stream blockSize
                let decryptedFirstBlock = Crypto.aes256CtrDecrypt keys.ClientToServerEncryptionKey iv firstBlock

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
                    // Calculate remaining bytes to read (including MAC)
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
                        let decryptedBlock = Crypto.aes256CtrDecrypt keys.ClientToServerEncryptionKey currentIv block
                        Array.Copy(decryptedBlock, 0, decryptedRemaining, blockStart, blockSize)

                        // Update IV
                        let mutable c = 1
                        for j = blockSize - 1 downto 0 do
                            if c > 0 then
                                let sum = int currentIv.[j] + c
                                currentIv.[j] <- byte (sum &&& 0xFF)
                                c <- sum >>> 8

                    // Combine decrypted data
                    let fullDecrypted = Array.append decryptedFirstBlock decryptedRemaining
                    let actualPacketData = fullDecrypted.[0..4 + packetLength - 1]

                    // Verify MAC
                    let seqBytes = Packet.writeUint32 state.ClientToServerSequence
                    let macInput = Array.append seqBytes actualPacketData
                    let expectedMac = Crypto.hmacSha256 keys.ClientToServerMacKey macInput

                    if not (Crypto.verifyHmacSha256 keys.ClientToServerMacKey macInput mac) then
                        return Error (ProtocolError "MAC verification failed")
                    else
                        let paddingLength = int fullDecrypted.[4]
                        let payloadLength = packetLength - paddingLength - 1
                        let payload = fullDecrypted.[5..5 + payloadLength - 1]
                        let newState = {
                            state with
                                ClientToServerSequence = state.ClientToServerSequence + 1u
                                ClientToServerIV = Some currentIv
                        }
                        return Ok (payload, newState)
            | _ ->
                return Error (ProtocolError "Encryption enabled but no keys available")
    }

    let writePacket (stream: NetworkStream) (state: TransportState) (payload: byte[]) = async {
        if not state.EncryptionEnabled then
            // Unencrypted packet - block size is 8 before encryption is enabled
            let packet = Packet.buildPacket payload 8
            do! stream.WriteAsync(packet, 0, packet.Length) |> Async.AwaitTask
            return Ok { state with ServerToClientSequence = state.ServerToClientSequence + 1u }
        else
            match state.Keys, state.ServerToClientIV with
            | Some keys, Some iv ->
                // Encrypted packet
                let blockSize = Constants.BlockSize
                let packet = Packet.buildPacket payload blockSize

                // Compute MAC before encryption (encrypt-then-MAC would be different)
                // SSH uses encrypt-and-MAC: MAC(seq || unencrypted_packet)
                let seqBytes = Packet.writeUint32 state.ServerToClientSequence
                let macInput = Array.append seqBytes packet
                let mac = Crypto.hmacSha256 keys.ServerToClientMacKey macInput

                // Encrypt entire packet at once using CTR mode
                let encrypted = Crypto.aes256CtrEncrypt keys.ServerToClientEncryptionKey iv packet

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

                // Send encrypted packet + MAC
                let output = Array.append encrypted mac
                do! stream.WriteAsync(output, 0, output.Length) |> Async.AwaitTask

                return Ok {
                    state with
                        ServerToClientSequence = state.ServerToClientSequence + 1u
                        ServerToClientIV = Some newIv
                }
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
