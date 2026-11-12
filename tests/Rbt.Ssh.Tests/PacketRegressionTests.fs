module Rbt.Ssh.Tests.PacketRegressionTests

open System
open System.Net
open System.Net.Sockets
open Xunit
open Rbt.Ssh

let private assertMalformed read =
    Assert.Throws<ArgumentException>(Action(fun () -> read ())) |> ignore

[<Fact>]
let ``SSH fields reject negative offset overflow and truncation`` () =
    let huge = [| 0xFFuy; 0xFFuy; 0xFFuy; 0xFFuy; 0uy |]
    for offset in [ -1; Int32.MaxValue; 2 ] do
        assertMalformed (fun () -> Packet.readUint32 huge offset |> ignore)
    for read in [ Packet.readBytes; (fun bytes offset -> Packet.readMpint bytes offset) ] do
        assertMalformed (fun () -> read huge 0 |> ignore)
        assertMalformed (fun () -> read [| 0uy; 0uy; 0uy; 3uy; 42uy |] 0 |> ignore)
    assertMalformed (fun () -> Packet.readString huge 0 |> ignore)
    assertMalformed (fun () -> Packet.readBool [||] 0 |> ignore)
    let data, next = Packet.readBytes [| 0uy; 0uy; 0uy; 0uy |] 0
    Assert.Empty(data)
    Assert.Equal(4, next)

[<Fact>]
let ``Known messages reject missing and trailing fields`` () =
    assertMalformed (fun () -> Packet.parseMessage [||] |> ignore)
    assertMalformed (fun () -> Packet.parseMessage [| MessageTypes.SSH_MSG_NEWKEYS; 0uy |] |> ignore)
    assertMalformed (fun () -> Packet.parseMessage [| MessageTypes.SSH_MSG_SERVICE_REQUEST; 0uy; 0uy; 0uy; 3uy; 65uy |] |> ignore)
    assertMalformed (fun () -> Packet.parseMessage [| MessageTypes.SSH_MSG_CHANNEL_OPEN; 0uy; 0uy; 0uy; 0uy |] |> ignore)
    assertMalformed (fun () -> Packet.parseMessage [| MessageTypes.SSH_MSG_CHANNEL_DATA; 0uy; 0uy; 0uy; 1uy; 0uy; 0uy; 0uy; 2uy; 65uy |] |> ignore)
    let kex = Packet.buildMessagePayload (KexInit(Array.zeroCreate 16, [], [], [], [], [], [], [], [], [], [], false))
    match Packet.parseMessage kex with
    | KexInit _ -> ()
    | other -> failwithf "Expected valid KEXINIT: %A" other
    assertMalformed (fun () -> Packet.parseMessage kex.[0..kex.Length - 2] |> ignore)

    let reserved = Array.copy kex
    reserved.[reserved.Length - 1] <- 1uy
    assertMalformed (fun () -> Packet.parseMessage reserved |> ignore)
    Assert.Equal(NewKeys, Packet.parseMessage [| MessageTypes.SSH_MSG_NEWKEYS |])
    match Packet.parseMessage [| 200uy; 1uy; 2uy |] with
    | RawMessage(200uy, [| 1uy; 2uy |]) -> ()
    | other -> failwithf "Unexpected opaque message: %A" other

[<Fact>]
let ``Packet builder rejects empty oversized and invalid block framing`` () =
    assertMalformed (fun () -> Packet.buildPacket [||] 8 |> ignore)
    assertMalformed (fun () -> Packet.buildPacket [| 21uy |] 0 |> ignore)
    assertMalformed (fun () -> Packet.buildPacket (Array.zeroCreate<byte> (int Constants.MaxSendPacketLength)) 8 |> ignore)
    for blockSize in [ 8; Constants.BlockSize ] do
        let packet = Packet.buildPacket [| MessageTypes.SSH_MSG_NEWKEYS |] blockSize
        let length = Packet.readUint32 packet 0
        Assert.Equal(int length + 4, packet.Length)
        Assert.Equal(0, packet.Length % blockSize)
        Assert.True(packet.[4] >= 4uy)

[<Fact>]
let ``Known channel requests reject truncation and trailing fields`` () =
    assertMalformed (fun () -> Packet.parseChannelRequest "exit-status" [| 0uy; 1uy |] |> ignore)
    assertMalformed (fun () -> Packet.parseChannelRequest "shell" [| 0uy |] |> ignore)
    assertMalformed (fun () -> Packet.parseChannelRequest "exec" [| 0uy; 0uy; 0uy; 3uy; 65uy |] |> ignore)
    match Packet.parseChannelRequest "exec" (Packet.buildChannelRequestData (Exec "echo ok")) with
    | Exec "echo ok" -> ()
    | other -> failwithf "Unexpected request: %A" other

let private withStreams run =
    use listener = new TcpListener(IPAddress.Loopback, 0)
    listener.Start()
    let port = (listener.LocalEndpoint :?> IPEndPoint).Port
    use sender = new TcpClient()
    sender.Connect(IPAddress.Loopback, port)
    use receiver = listener.AcceptTcpClient()
    use writeStream = sender.GetStream()
    use readStream = receiver.GetStream()
    run writeStream readStream sender

let private receiveWire wire state =
    withStreams (fun writeStream readStream sender ->
        writeStream.Write(wire, 0, wire.Length)
        sender.Client.Shutdown(SocketShutdown.Send)
        Transport.receiveMessageWithPayload readStream state |> Async.RunSynchronously)

let private assertWireError wire state =
    match receiveWire wire state with
    | Error (ProtocolError _ | ConnectionError _) -> ()
    | other -> failwithf "Expected structured packet error, got %A" other

let private rawPacket padding (payload: byte[]) =
    let length = 1 + payload.Length + padding
    Array.concat [| Packet.writeUint32 (uint32 length); [| byte padding |]; payload; Array.zeroCreate padding |]

[<Fact>]
let ``Outbound invalid payload returns a structured error`` () =
    withStreams (fun writeStream _ _ ->
        let state = TransportState.create "SSH-2.0-tests"
        for payload in [ [||]; Array.zeroCreate<byte> (int Constants.MaxSendPacketLength) ] do
            match Transport.writePacket writeStream state payload |> Async.RunSynchronously with
            | Error (ProtocolError _) -> ()
            | other -> failwithf "Expected outbound protocol error: %A" other)

[<Fact>]
let ``Unencrypted framing validates size alignment padding and EOF`` () =
    let state = TransportState.create "SSH-2.0-tests"
    for length in [ 0u; 7u; 8u; 11u; 13u; 16u; Constants.MaxReceivePacketLength + 1u; UInt32.MaxValue ] do
        assertWireError (Packet.writeUint32 length) state
    assertWireError [| 0uy; 0uy |] state
    let valid = rawPacket 10 [| MessageTypes.SSH_MSG_NEWKEYS |] // 16 bytes aligned
    let invalidPadding = Array.copy valid
    invalidPadding.[4] <- 3uy
    assertWireError invalidPadding state
    let emptyPayload = rawPacket 11 [||] // 16 bytes aligned
    assertWireError emptyPayload state
    assertWireError valid.[0..valid.Length - 2] state
    match receiveWire valid state with
    | Ok (NewKeys, payload, next) ->
        Assert.Equal<byte>([| MessageTypes.SSH_MSG_NEWKEYS |], payload)
        Assert.Equal(1u, next.ClientToServerSequence)
    | other -> failwithf "Expected valid unencrypted roundtrip: %A" other
    let malformed = Packet.buildPacket [| MessageTypes.SSH_MSG_NEWKEYS; 0uy |] 8
    assertWireError malformed state

[<Fact>]
let ``Inbound packets may exceed the RFC minimum and a full channel chunk builds outbound`` () =
    // A peer may send channel data larger than the 32 KB we advertise and the
    // 35000-byte RFC minimum; the receive cap is OpenSSH's 256 KB.
    let state = TransportState.create "SSH-2.0-tests"
    let data = Array.init 100000 byte
    let payload = Packet.buildMessagePayload (ChannelData(0u, data))
    let padding = 8 - ((5 + payload.Length) % 8) + 8
    match receiveWire (rawPacket padding payload) state with
    | Ok (ChannelData(0u, received), _, _) -> Assert.Equal<byte>(data, received)
    | other -> failwithf "Large inbound packet was not accepted: %A" other
    // Outbound: a DefaultMaxPacketSize chunk with the largest channel header
    // (extended data) builds at every block size and stays within the RFC size.
    let chunk = Array.zeroCreate<byte> (int Constants.DefaultMaxPacketSize)
    let extended = Packet.buildMessagePayload (ChannelExtendedData(0u, 1u, chunk))
    for blockSize in [ 8; Constants.BlockSize ] do
        let packet = Packet.buildPacket extended blockSize
        Assert.True(Packet.readUint32 packet 0 <= Constants.MaxSendPacketLength)

let private keys = {
    ClientToServerIV = Array.init Constants.IvLength byte
    ServerToClientIV = Array.init Constants.IvLength byte
    ClientToServerEncryptionKey = Array.init Constants.AesKeyLength byte
    ServerToClientEncryptionKey = Array.init Constants.AesKeyLength byte
    ClientToServerMacKey = Array.init Constants.MacLength byte
    ServerToClientMacKey = Array.init Constants.MacLength byte
}

let private encryptedState = Transport.enableEncryption (TransportState.create "SSH-2.0-tests") keys

let private encryptWire plain =
    let mac = Crypto.hmacSha256 keys.ClientToServerMacKey (Array.append (Packet.writeUint32 0u) plain)
    Array.append (Crypto.aes256CtrEncrypt keys.ClientToServerEncryptionKey keys.ClientToServerIV plain) mac

[<Fact>]
let ``Encrypted framing rejects malformed lengths padding and incomplete MAC`` () =
    for length in [ 0u; 11u; 13u; 17u; Constants.MaxReceivePacketLength + 1u; UInt32.MaxValue ] do
        let firstBlock = Array.zeroCreate<byte> Constants.BlockSize
        Array.Copy(Packet.writeUint32 length, firstBlock, 4)
        let encrypted = Crypto.aes256CtrEncrypt keys.ClientToServerEncryptionKey keys.ClientToServerIV firstBlock
        assertWireError encrypted encryptedState
    let valid = rawPacket 10 [| MessageTypes.SSH_MSG_NEWKEYS |]
    let invalidPadding = Array.copy valid
    invalidPadding.[4] <- 3uy
    assertWireError (encryptWire invalidPadding) encryptedState
    assertWireError (encryptWire (rawPacket 11 [||])) encryptedState
    let encrypted = encryptWire valid
    assertWireError encrypted.[0..encrypted.Length - 1 - Constants.MacLength] encryptedState
    assertWireError encrypted.[0..encrypted.Length - 2] encryptedState
    let badMac = Array.copy encrypted
    badMac.[badMac.Length - 1] <- badMac.[badMac.Length - 1] ^^^ 1uy
    assertWireError badMac encryptedState
    match receiveWire encrypted encryptedState with
    | Ok (NewKeys, payload, next) ->
        Assert.Equal<byte>([| MessageTypes.SSH_MSG_NEWKEYS |], payload)
        Assert.Equal(1u, next.ClientToServerSequence)
    | other -> failwithf "Expected valid encrypted roundtrip: %A" other

[<Fact>]
let ``Transport writes roundtrip both directions with exact payload`` () =
    for encrypted in [ false; true ] do
        withStreams (fun writeStream readStream _ ->
            let outgoing = if encrypted then Transport.enableEncryption (TransportState.createClient "SSH-2.0-tests") keys else TransportState.createClient "SSH-2.0-tests"
            let incoming = if encrypted then encryptedState else TransportState.create "SSH-2.0-tests"
            let message = ServiceRequest "ssh-userauth"
            let written = Transport.sendMessage writeStream outgoing message |> Async.RunSynchronously
            match written, Transport.receiveMessageWithPayload readStream incoming |> Async.RunSynchronously with
            | Ok nextWrite, Ok (ServiceRequest service, payload, nextRead) ->
                Assert.Equal("ssh-userauth", service)
                Assert.Equal<byte>(Packet.buildMessagePayload message, payload)
                Assert.Equal(1u, nextWrite.ClientToServerSequence)
                Assert.Equal(1u, nextRead.ClientToServerSequence)
            | other -> failwithf "Transport roundtrip failed: %A" other)
