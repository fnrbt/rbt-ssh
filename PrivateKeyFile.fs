namespace Rbt.Ssh

open System
open System.Security.Cryptography
open System.Text

/// OpenSSH private key files (`-----BEGIN OPENSSH PRIVATE KEY-----`, the
/// openssh-key-v1 format ssh-keygen writes) as client keys for public-key
/// authentication. Ed25519 and RSA keys without a passphrase.
module PrivateKeyFile =

    let private magic = Encoding.ASCII.GetBytes "openssh-key-v1\000"

    type private Reader(data: byte[]) =
        let mutable offset = 0
        member _.Remaining = data.Length - offset
        member _.UInt32() =
            if offset + 4 > data.Length then failwith "truncated key file"
            let value =
                (uint32 data.[offset] <<< 24) ||| (uint32 data.[offset + 1] <<< 16)
                ||| (uint32 data.[offset + 2] <<< 8) ||| uint32 data.[offset + 3]
            offset <- offset + 4
            value
        member this.Bytes() =
            let length = int (this.UInt32())
            if length < 0 || offset + length > data.Length then failwith "truncated key file"
            let value = data.[offset .. offset + length - 1]
            offset <- offset + length
            value
        member this.Text() = Encoding.ASCII.GetString(this.Bytes())
        member _.Skip(count: int) =
            if offset + count > data.Length then failwith "truncated key file"
            offset <- offset + count

    /// An SSH mpint as a big-endian unsigned integer without leading zeros.
    let private unsigned (mpint: byte[]) =
        let start = mpint |> Array.tryFindIndex ((<>) 0uy) |> Option.defaultValue (mpint.Length - 1)
        if mpint.Length = 0 then [| 0uy |] else mpint.[start..]

    /// Left-pad a big-endian integer to `length` bytes, as RSAParameters needs.
    let private padTo (length: int) (value: byte[]) =
        if value.Length >= length then value
        else Array.append (Array.zeroCreate (length - value.Length)) value

    let private toBig (value: byte[]) = Numerics.BigInteger(value, isUnsigned = true, isBigEndian = true)
    let private fromBig (value: Numerics.BigInteger) = value.ToByteArray(isUnsigned = true, isBigEndian = true)

    let private rsaKey (reader: Reader) =
        let n = unsigned (reader.Bytes())
        let e = unsigned (reader.Bytes())
        let d = unsigned (reader.Bytes())
        let iqmp = unsigned (reader.Bytes())
        let p = unsigned (reader.Bytes())
        let q = unsigned (reader.Bytes())
        let half = (n.Length + 1) / 2
        let parameters =
            RSAParameters(
                Modulus = n,
                Exponent = e,
                D = padTo n.Length d,
                P = padTo half p,
                Q = padTo half q,
                DP = padTo half (fromBig (Numerics.BigInteger.Remainder(toBig d, toBig p - Numerics.BigInteger.One))),
                DQ = padTo half (fromBig (Numerics.BigInteger.Remainder(toBig d, toBig q - Numerics.BigInteger.One))),
                InverseQ = padTo half iqmp)
        // Fail here, not at the first signature, when the numbers do not form a key.
        use rsa = RSA.Create()
        rsa.ImportParameters parameters
        { KeyType = HostKeyType.Rsa
          PublicKeyBlob = Crypto.buildRsaPublicKeyBlob parameters
          PrivateKey = parameters :> obj }

    let private ed25519Key (reader: Reader) =
        let publicKey = reader.Bytes()
        let secret = reader.Bytes()
        if publicKey.Length <> 32 || secret.Length <> 64 then failwith "malformed ssh-ed25519 key"
        // OpenSSH stores the 32-byte seed followed by the public key.
        let seed = secret.[0..31]
        { KeyType = HostKeyType.Ed25519
          PublicKeyBlob = Crypto.buildEd25519PublicKeyBlob publicKey
          PrivateKey = (publicKey, seed) :> obj }

    let private decodeArmor (text: string) =
        let lines =
            text.Replace("\r", "").Split('\n')
            |> Array.map _.Trim()
            |> Array.filter (String.IsNullOrWhiteSpace >> not)
        let first = lines |> Array.tryFindIndex ((=) "-----BEGIN OPENSSH PRIVATE KEY-----")
        let last = lines |> Array.tryFindIndex ((=) "-----END OPENSSH PRIVATE KEY-----")
        match first, last with
        | Some first, Some last when last > first ->
            Ok(Convert.FromBase64String(String.Concat(lines.[first + 1 .. last - 1])))
        | _ when lines |> Array.exists (fun line -> line.StartsWith "-----BEGIN" && line.Contains "PRIVATE KEY") ->
            Error "only OpenSSH-format private keys are supported (ssh-keygen's default; convert a PEM key with ssh-keygen -p -f <file>)"
        | _ -> Error "not an OpenSSH private key (expected -----BEGIN OPENSSH PRIVATE KEY-----)"

    /// The client key in an OpenSSH private key file.
    let parse (text: string) : Result<HostKey, string> =
        if String.IsNullOrWhiteSpace text then Error "the private key is empty"
        else
            match decodeArmor text with
            | Error message -> Error message
            | Ok data ->
                try
                    if data.Length < magic.Length || data.[0 .. magic.Length - 1] <> magic then
                        Error "not an openssh-key-v1 file"
                    else
                        let reader = Reader(data)
                        reader.Skip magic.Length
                        let cipher = reader.Text()
                        let kdf = reader.Text()
                        reader.Bytes() |> ignore // kdf options
                        if cipher <> "none" || kdf <> "none" then
                            Error "the private key has a passphrase; use a key without one"
                        else
                            let count = reader.UInt32()
                            if count <> 1u then Error $"the key file holds {count} keys; expected one"
                            else
                                reader.Bytes() |> ignore // public key, repeated in the private section
                                let secret = Reader(reader.Bytes())
                                if secret.UInt32() <> secret.UInt32() then Error "the private key's check values differ (corrupt file)"
                                else
                                    match secret.Text() with
                                    | "ssh-ed25519" -> Ok(ed25519Key secret)
                                    | "ssh-rsa" -> Ok(rsaKey secret)
                                    | other -> Error $"{other} keys are not supported; use ssh-ed25519 or ssh-rsa"
                with ex -> Error $"could not read the private key: {ex.Message}"

    /// The `SHA256:...` fingerprint ssh-keygen -l shows for a public key blob.
    let fingerprint (publicKeyBlob: byte[]) =
        "SHA256:" + Convert.ToBase64String(SHA256.HashData publicKeyBlob).TrimEnd('=')
