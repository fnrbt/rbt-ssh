module Rbt.Ssh.Tests.CryptoRegressionTests

open System
open System.Net
open System.Net.Sockets
open Xunit
open Rbt.Ssh

let private requireOk = function Ok value -> value | Error error -> failwithf "%A" error

[<Fact>]
let ``key derivation uses canonical positive mpints`` () =
    let h = Array.create 32 3uy
    let sid = Array.create 32 4uy
    for secret, encoded in [
        [||], [|0uy; 0uy; 0uy; 0uy|]
        [|0uy; 0uy|], [|0uy; 0uy; 0uy; 0uy|]
        [|0uy; 0uy; 1uy|], [|0uy; 0uy; 0uy; 1uy; 1uy|]
        [|0uy; 0x80uy|], [|0uy; 0uy; 0uy; 2uy; 0uy; 0x80uy|] ] do
        Assert.True((encoded = Crypto.encodePositiveMpint secret))
        let expected = Crypto.sha256 (Array.concat [|encoded; h; [|byte 'A'|]; sid|])
        Assert.True((expected = Crypto.deriveKey secret h sid 'A' 32))

[<Fact>]
let ``signature algorithm must match the requested algorithm and key type`` () =
    let rsa = Crypto.createRsaHostKey 2048
    let data = [|1uy; 2uy; 3uy|]
    let sha256 = Crypto.signWithHostKey rsa data (Some Algorithms.HOSTKEY_RSA_SHA2_256)
    let sha512 = Crypto.signWithHostKey rsa data (Some Algorithms.HOSTKEY_RSA_SHA2_512)
    Assert.True(Crypto.verifyPublicKeySignature Algorithms.HOSTKEY_RSA_SHA2_256 rsa.PublicKeyBlob sha256 data)
    Assert.False(Crypto.verifyPublicKeySignature Algorithms.HOSTKEY_RSA_SHA2_512 rsa.PublicKeyBlob sha256 data)
    Assert.False(Crypto.verifyPublicKeySignature Algorithms.HOSTKEY_RSA_SHA2_256 rsa.PublicKeyBlob sha512 data)
    use signer = System.Security.Cryptography.RSA.Create()
    signer.ImportParameters(rsa.PrivateKey :?> System.Security.Cryptography.RSAParameters)
    let sha1 = signer.SignData(data, System.Security.Cryptography.HashAlgorithmName.SHA1, System.Security.Cryptography.RSASignaturePadding.Pkcs1)
    let signature = Crypto.buildRsaSignatureBlob "ssh-rsa" sha1
    Assert.True(Crypto.verifyPublicKeySignature "ssh-rsa" rsa.PublicKeyBlob signature data)
    Assert.False(Crypto.verifyPublicKeySignature "rsa-sha2-256" rsa.PublicKeyBlob signature data)
    let ed = Crypto.createEd25519HostKey()
    let wrongLabel = Crypto.buildRsaSignatureBlob "rsa-sha2-256" (Crypto.signEd25519 (snd (ed.PrivateKey :?> (byte[] * byte[]))) data)
    Assert.False(Crypto.verifyPublicKeySignature "rsa-sha2-256" ed.PublicKeyBlob wrongLabel data)

[<Fact>]
let ``rsa sha1 is not advertised for host keys`` () =
    match KeyExchange.createServerKexInit ["rsa"] with
    | KexInit(_, _, hostKeys, _, _, _, _, _, _, _, _, _) ->
        Assert.DoesNotContain(Algorithms.HOSTKEY_SSH_RSA, hostKeys)
        Assert.Contains(Algorithms.HOSTKEY_RSA_SHA2_256, hostKeys)
    | _ -> failwith "expected KEXINIT"

[<Fact>]
let ``optimistic guess compares both first algorithms`` () =
    let make follows kex keys = KexInit(Array.zeroCreate 16, kex, keys, [], [], [], [], [], [], [], [], follows)
    Assert.False(KeyExchange.incorrectGuess (make false ["wrong"] ["wrong"]) "k" "h")
    Assert.False(KeyExchange.incorrectGuess (make true ["k"] ["h"]) "k" "h")
    Assert.True(KeyExchange.incorrectGuess (make true ["wrong"; "k"] ["h"]) "k" "h")
    Assert.True(KeyExchange.incorrectGuess (make true ["k"] ["wrong"; "h"]) "k" "h")

[<Fact>]
let ``rejected public key probe with repeated banners falls back to password`` () =
    use listener = new TcpListener(IPAddress.Loopback, 0)
    listener.Start()
    let port = (listener.LocalEndpoint :?> IPEndPoint).Port
    use client = new TcpClient()
    client.Connect(IPAddress.Loopback, port)
    use server = listener.AcceptTcpClient()
    use clientStream = client.GetStream()
    use serverStream = server.GetStream()
    let serverTask = Async.StartAsTask(async {
        let mutable state = TransportState.create "server"
        let receive () = async {
            let! result = Transport.receiveMessage serverStream state
            let msg, next = requireOk result
            state <- next
            return msg
        }
        let send msg = async {
            let! result = Transport.sendMessage serverStream state msg
            state <- requireOk result
        }
        let! service = receive ()
        match service with ServiceRequest "ssh-userauth" -> () | _ -> failwithf "unexpected %A" service
        do! send (UserAuthBanner("one", ""))
        do! send (UserAuthBanner("two", ""))
        do! send (ServiceAccept "ssh-userauth")
        let! probe = receive ()
        match probe with UserAuthRequest(_, _, "publickey", PublicKey(_, _, None)) -> () | _ -> failwithf "unexpected %A" probe
        do! send (UserAuthBanner("three", ""))
        do! send (UserAuthBanner("four", ""))
        do! send (UserAuthFailure(["password"], false))
        let! password = receive ()
        match password with UserAuthRequest(_, _, "password", Password "secret") -> () | _ -> failwithf "unexpected %A" password
        do! send (UserAuthBanner("five", ""))
        do! send (UserAuthBanner("six", ""))
        do! send UserAuthSuccess
    })
    let config: ClientAuth.ClientAuthConfig = { Username = "user"; Methods = [ClientAuth.PublicKeyAuth(Crypto.createEd25519HostKey()); ClientAuth.PasswordAuth "secret"] }
    let result = ClientAuth.authenticate clientStream (TransportState.createClient "client") [|1uy|] config |> fun work -> Async.RunSynchronously(work, 5000)
    requireOk result |> ignore
    Assert.True(serverTask.Wait(TimeSpan.FromSeconds 5.0))

[<Fact>]
let ``server ignores wrong optimistic packet and hashes exact client kexinit`` () =
    use listener = new TcpListener(IPAddress.Loopback, 0)
    listener.Start()
    let port = (listener.LocalEndpoint :?> IPEndPoint).Port
    use client = new TcpClient()
    client.Connect(IPAddress.Loopback, port)
    use server = listener.AcceptTcpClient()
    use clientStream = client.GetStream()
    use serverStream = server.GetStream()
    let hostKey = Crypto.createEd25519HostKey()
    let serverState = { TransportState.create "server" with ClientVersion = Some "client" }
    let serverTask = KeyExchange.handleKeyExchange serverStream serverState [hostKey] |> Async.StartAsTask
    let run work = Async.RunSynchronously(work, 5000) |> requireOk
    let mutable state = { TransportState.createClient "client" with ServerVersion = "server" }
    let serverInit, serverPayload, next = run (Transport.receiveMessageWithPayload clientStream state)
    state <- next
    let clientInit =
        match ClientKeyExchange.createClientKexInit () with
        | KexInit(cookie, kex, keys, a, b, c, d, e, f, g, h, _) ->
            KexInit(cookie, "unsupported-kex" :: kex, keys, a, b, c, d, e, f, g, h, true)
        | _ -> failwith "expected KEXINIT"
    let payload = Packet.buildMessagePayload clientInit
    payload.[payload.Length - 5] <- 2uy
    state <- run (Transport.writePacket clientStream state payload)
    state <- run (Transport.writePacket clientStream state [|30uy|])
    let publicKey, privateKey = Crypto.generateCurve25519KeyPair()
    state <- run (Transport.sendMessage clientStream state (KexEcdhInit publicKey))
    let reply, next = run (Transport.receiveMessage clientStream state)
    state <- next
    match reply with
    | KexEcdhReply(keyBlob, peerKey, signature) ->
        let secret = Crypto.computeCurve25519SharedSecret privateKey peerKey |> Option.get
        let hash = KeyExchange.computeExchangeHash "client" "server" payload serverPayload keyBlob publicKey peerKey secret
        Assert.True(Crypto.verifyPublicKeySignature "ssh-ed25519" keyBlob signature hash)
    | _ -> failwithf "unexpected %A" reply
    let newKeys, next = run (Transport.receiveMessage clientStream state)
    state <- next
    Assert.Equal(NewKeys, newKeys)
    state <- run (Transport.sendMessage clientStream state NewKeys)
    Assert.True(serverTask.Wait(TimeSpan.FromSeconds 5.0))
    serverTask.Result |> requireOk |> ignore
