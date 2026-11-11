/// Client tests against the OpenSSH server tests/setup-sshd.sh provisions.
/// Without its keys (tests/keys) the tests that need the server do nothing.
module Rbt.Ssh.Tests.ClientTests

open System
open System.IO
open System.Text
open Xunit
open Rbt.Ssh

let private keys =
    let rec up (dir: DirectoryInfo) =
        if isNull dir then None
        elif File.Exists(Path.Combine(dir.FullName, "Rbt.Ssh.fsproj")) then Some(Path.Combine(dir.FullName, "tests", "keys"))
        else up dir.Parent
    up (DirectoryInfo AppContext.BaseDirectory)

let private keyFile name = keys |> Option.map (fun dir -> Path.Combine(dir, name)) |> Option.filter File.Exists
let private port = match Environment.GetEnvironmentVariable "RBT_SSH_PORT" with null | "" -> 52222 | value -> int value

/// The fingerprint ssh-keygen wrote next to the key, from its .pub file.
let private publicFingerprint (pubFile: string) =
    let blob = Convert.FromBase64String((File.ReadAllText pubFile).Split(' ').[1])
    PrivateKeyFile.fingerprint blob

let private parseOrFail path =
    match PrivateKeyFile.parse (File.ReadAllText path) with
    | Ok key -> key
    | Error message -> failwith message

[<Fact>]
let ``an ed25519 key file parses to its public key`` () =
    match keyFile "id_ed25519" with
    | None -> ()
    | Some path ->
        let key = parseOrFail path
        Assert.Equal(HostKeyType.Ed25519, key.KeyType)
        Assert.Equal(publicFingerprint (path + ".pub"), PrivateKeyFile.fingerprint key.PublicKeyBlob)

[<Fact>]
let ``an rsa key file parses to its public key`` () =
    match keyFile "id_rsa" with
    | None -> ()
    | Some path ->
        let key = parseOrFail path
        Assert.Equal(HostKeyType.Rsa, key.KeyType)
        Assert.Equal(publicFingerprint (path + ".pub"), PrivateKeyFile.fingerprint key.PublicKeyBlob)

[<Fact>]
let ``non-OpenSSH and empty key text is refused with a reason`` () =
    for text in [ ""; "hello"; "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"
                  "-----BEGIN OPENSSH PRIVATE KEY-----\nnot base64\n-----END OPENSSH PRIVATE KEY-----" ] do
        match PrivateKeyFile.parse text with
        | Ok _ -> failwith $"accepted {text}"
        | Error message -> Assert.False(String.IsNullOrWhiteSpace message)

let private connect (methods: ClientAuth.ClientAuthMethod list) (verification: HostKeyVerification) =
    let config = { ClientConfig.defaults with Username = "tester"; HostKeyVerification = verification }
    Client.connectAsync "127.0.0.1" port config { Username = "tester"; Methods = methods }
    |> Async.RunSynchronously

let private hostFingerprint () =
    keyFile "host_ed25519.fp" |> Option.map (fun path -> (File.ReadAllText path).Trim())

let private execOn methods =
    match hostFingerprint () with
    | None -> None
    | Some fp ->
        match connect methods (Fingerprint [ fp ]) with
        | Error e -> failwith $"connect failed: {e}"
        | Ok client ->
            try
                match Client.exec client "printf out; printf err >&2; exit 3" |> Async.RunSynchronously with
                | Error e -> failwith $"exec failed: {e}"
                | Ok result -> Some result
            finally
                Client.disconnect client |> Async.RunSynchronously

[<Fact>]
let ``an ed25519 key signs in and runs a command`` () =
    match keyFile "id_ed25519" with
    | None -> ()
    | Some path ->
        match execOn [ ClientAuth.PublicKeyAuth(parseOrFail path) ] with
        | None -> ()
        | Some (code, stdout, stderr) ->
            Assert.Equal(3u, code)
            Assert.Equal("out", Encoding.UTF8.GetString stdout)
            Assert.Equal("err", Encoding.UTF8.GetString stderr)

[<Fact>]
let ``an rsa key signs in and runs a command`` () =
    match keyFile "id_rsa" with
    | None -> ()
    | Some path ->
        match execOn [ ClientAuth.PublicKeyAuth(parseOrFail path) ] with
        | None -> ()
        | Some (code, stdout, _) ->
            Assert.Equal(3u, code)
            Assert.Equal("out", Encoding.UTF8.GetString stdout)

[<Fact>]
let ``a password signs in`` () =
    match execOn [ ClientAuth.PasswordAuth "secret" ] with
    | None -> ()
    | Some (code, _, _) -> Assert.Equal(3u, code)

[<Fact>]
let ``a host key that is not the pinned one is refused`` () =
    match hostFingerprint (), keyFile "id_ed25519" with
    | Some _, Some path ->
        match connect [ ClientAuth.PublicKeyAuth(parseOrFail path) ] (Fingerprint [ "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ]) with
        | Ok client ->
            Client.disconnect client |> Async.RunSynchronously
            failwith "connected to a server whose host key was not pinned"
        | Error _ -> ()
    | _ -> ()

[<Fact>]
let ``output past the initial window keeps flowing`` () =
    match hostFingerprint (), keyFile "id_ed25519" with
    | Some fp, Some path ->
        match connect [ ClientAuth.PublicKeyAuth(parseOrFail path) ] (Fingerprint [ fp ]) with
        | Error e -> failwith $"connect failed: {e}"
        | Ok client ->
            try
                // 6 MB on stdout, three times the 2 MB initial window.
                let run = Client.exec client "head -c 6291456 /dev/zero" |> Async.StartAsTask
                Assert.True(run.Wait(TimeSpan.FromSeconds 30.0), "exec stalled")
                match run.Result with
                | Error e -> failwith $"exec failed: {e}"
                | Ok (code, stdout, _) ->
                    Assert.Equal(0u, code)
                    Assert.Equal(6291456, stdout.Length)
            finally
                Client.disconnect client |> Async.RunSynchronously
    | _ -> ()

[<Fact>]
let ``one connection runs several commands`` () =
    match hostFingerprint (), keyFile "id_ed25519" with
    | Some fp, Some path ->
        match connect [ ClientAuth.PublicKeyAuth(parseOrFail path) ] (Fingerprint [ fp ]) with
        | Error e -> failwith $"connect failed: {e}"
        | Ok client ->
            try
                for i in 1 .. 3 do
                    match Client.exec client $"echo {i}" |> Async.RunSynchronously with
                    | Error e -> failwith $"exec {i} failed: {e}"
                    | Ok (_, stdout, _) -> Assert.Equal($"{i}\n", Encoding.UTF8.GetString stdout)
            finally
                Client.disconnect client |> Async.RunSynchronously
    | _ -> ()

[<Fact>]
let ``a rejected key falls back to password authentication`` () =
    match execOn [ ClientAuth.PublicKeyAuth(Crypto.createEd25519HostKey()); ClientAuth.PasswordAuth "secret" ] with
    | None -> ()
    | Some (code, stdout, stderr) ->
        Assert.Equal(3u, code)
        Assert.Equal("out", Encoding.UTF8.GetString stdout)
        Assert.Equal("err", Encoding.UTF8.GetString stderr)

[<Fact>]
let ``full duplex input crosses the channel window without corrupting transport`` () =
    match hostFingerprint (), keyFile "id_ed25519" with
    | Some fp, Some path ->
        match connect [ ClientAuth.PublicKeyAuth(parseOrFail path) ] (Fingerprint [ fp ]) with
        | Error e -> failwith $"connect failed: {e}"
        | Ok client ->
            let requireOk = function Ok value -> value | Error error -> failwithf "%A" error
            try
                let channelId = Client.openChannel client |> Async.RunSynchronously |> requireOk
                Client.requestExec client channelId "cat" |> Async.RunSynchronously |> requireOk
                let expected = Array.init (3 * 1024 * 1024) (fun index -> byte (index % 251))
                let stdout = System.Collections.Generic.List<byte>()
                let stderr = System.Collections.Generic.List<byte>()
                let mutable exit = None
                let callbacks = {
                    OnStdout = fun id data -> async {
                        Assert.Equal(channelId, id)
                        stdout.AddRange(data)
                    }
                    OnStderr = fun _ data -> async { stderr.AddRange(data) }
                    OnExit = fun id code -> async { exit <- Some (id, code) }
                    OnChannelClose = fun _ -> async { () }
                }
                let receiving = Client.receiveLoop client callbacks |> Async.StartAsTask
                let sending = Async.StartAsTask(async {
                    let! sent = Client.sendData client channelId expected
                    requireOk sent
                    return! Client.sendEof client channelId
                })
                Assert.True(sending.Wait(TimeSpan.FromSeconds 30.0), "stdin stalled")
                requireOk sending.Result
                Assert.True(receiving.Wait(TimeSpan.FromSeconds 30.0), "stdout stalled")
                requireOk receiving.Result
                Assert.Equal(Some (channelId, 0u), exit)
                Assert.Empty(stderr)
                Assert.True((expected = stdout.ToArray()), "echoed bytes differ from stdin")
            finally
                Client.disconnect client |> Async.RunSynchronously
    | _ -> ()

[<Fact>]
let ``default host trust rejects an otherwise valid server`` () =
    match hostFingerprint () with
    | None -> ()
    | Some _ ->
        let config = { ClientConfig.defaults with Username = "tester" }
        let result =
            Client.connectAsync "127.0.0.1" port config
                { Username = "tester"; Methods = [ ClientAuth.PasswordAuth "secret" ] }
            |> Async.RunSynchronously
        match result with
        | Error (CryptoError _) -> ()
        | Error error -> failwithf "unexpected failure: %A" error
        | Ok client ->
            Client.disconnect client |> Async.RunSynchronously
            failwith "authenticated without configuring host trust"
