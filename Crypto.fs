namespace Ssh

open System
open System.Security.Cryptography
open NSec.Cryptography
open Org.BouncyCastle.Crypto.Agreement
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Security

module Crypto =

    // Curve25519 key exchange using BouncyCastle
    let generateCurve25519KeyPair () =
        let generator = X25519KeyPairGenerator()
        generator.Init(X25519KeyGenerationParameters(SecureRandom()))
        let keyPair = generator.GenerateKeyPair()
        let publicKey = (keyPair.Public :?> X25519PublicKeyParameters).GetEncoded()
        let privateKey = (keyPair.Private :?> X25519PrivateKeyParameters).GetEncoded()
        (publicKey, privateKey)

    let computeCurve25519SharedSecret (privateKey: byte[]) (peerPublicKey: byte[]) =
        try
            let privKeyParams = X25519PrivateKeyParameters(privateKey, 0)
            let pubKeyParams = X25519PublicKeyParameters(peerPublicKey, 0)
            let agreement = X25519Agreement()
            agreement.Init(privKeyParams)
            let sharedSecret = Array.zeroCreate<byte> agreement.AgreementSize
            agreement.CalculateAgreement(pubKeyParams, sharedSecret, 0)
            Option.Some(sharedSecret)
        with ex ->
            printfn "computeCurve25519SharedSecret error: %s" ex.Message
            Option.None

    // Ed25519 operations using NSec
    let generateEd25519KeyPair () =
        let algorithm = SignatureAlgorithm.Ed25519
        let creationParams = KeyCreationParameters(ExportPolicy = KeyExportPolicies.AllowPlaintextExport)
        use key = Key.Create(algorithm, &creationParams)
        let publicKey = key.Export(KeyBlobFormat.RawPublicKey)
        let privateKey = key.Export(KeyBlobFormat.RawPrivateKey)
        (publicKey, privateKey)

    let signEd25519 (privateKey: byte[]) (data: byte[]) =
        let algorithm = SignatureAlgorithm.Ed25519
        use key = Key.Import(algorithm, privateKey, KeyBlobFormat.RawPrivateKey)
        algorithm.Sign(key, data)

    let verifyEd25519 (publicKey: byte[]) (data: byte[]) (signature: byte[]) =
        let algorithm = SignatureAlgorithm.Ed25519
        let pubKey = PublicKey.Import(algorithm, publicKey, KeyBlobFormat.RawPublicKey)
        algorithm.Verify(pubKey, data, signature)

    // RSA operations using System.Security.Cryptography
    let generateRsaKeyPair (keySizeBits: int) =
        use rsa = RSA.Create(keySizeBits)
        let parameters = rsa.ExportParameters(true)
        (rsa.ExportRSAPublicKey(), parameters)

    let signRsaSha256 (parameters: RSAParameters) (data: byte[]) =
        use rsa = RSA.Create()
        rsa.ImportParameters(parameters)
        rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)

    let signRsaSha512 (parameters: RSAParameters) (data: byte[]) =
        use rsa = RSA.Create()
        rsa.ImportParameters(parameters)
        rsa.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)

    let verifyRsaSha1 (publicKeyBlob: byte[]) (data: byte[]) (signature: byte[]) =
        use rsa = RSA.Create()
        let mutable bytesRead = 0
        rsa.ImportRSAPublicKey(ReadOnlySpan(publicKeyBlob), &bytesRead)
        rsa.VerifyData(data, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1)

    let verifyRsaSha256 (publicKeyBlob: byte[]) (data: byte[]) (signature: byte[]) =
        use rsa = RSA.Create()
        let mutable bytesRead = 0
        rsa.ImportRSAPublicKey(ReadOnlySpan(publicKeyBlob), &bytesRead)
        rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)

    let verifyRsaSha512 (publicKeyBlob: byte[]) (data: byte[]) (signature: byte[]) =
        use rsa = RSA.Create()
        let mutable bytesRead = 0
        rsa.ImportRSAPublicKey(ReadOnlySpan(publicKeyBlob), &bytesRead)
        rsa.VerifyData(data, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)

    // AES-256-CTR encryption/decryption
    // CTR mode processes blocks by encrypting counter and XORing with plaintext
    let aesCtrTransform (key: byte[]) (iv: byte[]) (data: byte[]) =
        use aes = Aes.Create()
        aes.Key <- key
        aes.Mode <- CipherMode.ECB  // We implement CTR manually
        aes.Padding <- PaddingMode.None

        let counter = Array.copy iv
        let output = Array.zeroCreate<byte> data.Length
        let blockSize = 16
        let encryptor = aes.CreateEncryptor()

        let incrementCounter () =
            // Increment counter as big-endian
            let mutable carry = 1
            for i = blockSize - 1 downto 0 do
                if carry > 0 then
                    let sum = int counter.[i] + carry
                    counter.[i] <- byte (sum &&& 0xFF)
                    carry <- sum >>> 8

        let mutable offset = 0
        while offset < data.Length do
            let blockLen = min blockSize (data.Length - offset)
            let encryptedCounter = Array.zeroCreate<byte> blockSize
            encryptor.TransformBlock(counter, 0, blockSize, encryptedCounter, 0) |> ignore

            for i = 0 to blockLen - 1 do
                output.[offset + i] <- data.[offset + i] ^^^ encryptedCounter.[i]

            incrementCounter()
            offset <- offset + blockSize

        output

    // For CTR mode, encryption and decryption are the same operation
    let aes256CtrEncrypt = aesCtrTransform
    let aes256CtrDecrypt = aesCtrTransform

    // HMAC-SHA2-256
    let hmacSha256 (key: byte[]) (data: byte[]) =
        use hmac = new HMACSHA256(key)
        hmac.ComputeHash(data)

    let verifyHmacSha256 (key: byte[]) (data: byte[]) (mac: byte[]) =
        let computed = hmacSha256 key data
        CryptographicOperations.FixedTimeEquals(ReadOnlySpan(computed), ReadOnlySpan(mac))

    // SHA-256 hash
    let sha256 (data: byte[]) =
        use hasher = SHA256.Create()
        hasher.ComputeHash(data)

    // Random bytes generation
    let randomBytes (count: int) =
        let bytes = Array.zeroCreate<byte> count
        RandomNumberGenerator.Fill(Span(bytes))
        bytes

    // SSH key derivation (RFC 4253 section 7.2)
    // K || H || X || session_id, where X is a single character
    let deriveKey (sharedSecret: byte[]) (exchangeHash: byte[]) (sessionId: byte[]) (keyChar: char) (keyLength: int) =
        // Build the hash input: K (mpint) || H || char || session_id
        // For SSH, K is encoded as mpint
        let kMpint =
            // SSH mpint: if MSB is set, prepend 0x00
            let needsPadding = sharedSecret.Length > 0 && (sharedSecret.[0] &&& 0x80uy) <> 0uy
            if needsPadding then
                Array.concat [| [| 0uy |]; sharedSecret |]
            else
                sharedSecret

        let kLenBytes = BitConverter.GetBytes(uint32 kMpint.Length)
        if BitConverter.IsLittleEndian then
            Array.Reverse(kLenBytes)

        let baseInput = Array.concat [|
            kLenBytes
            kMpint
            exchangeHash
            [| byte keyChar |]
            sessionId
        |]

        let mutable key = sha256 baseInput

        // If we need more bytes, keep hashing K || H || K1 || K2 || ...
        while key.Length < keyLength do
            let extendInput = Array.concat [|
                kLenBytes
                kMpint
                exchangeHash
                key
            |]
            key <- Array.append key (sha256 extendInput)

        key.[0..keyLength-1]

    // Derive all session keys
    let deriveAllKeys (sharedSecret: byte[]) (exchangeHash: byte[]) (sessionId: byte[]) : DerivedKeys =
        {
            ClientToServerIV = deriveKey sharedSecret exchangeHash sessionId 'A' Constants.IvLength
            ServerToClientIV = deriveKey sharedSecret exchangeHash sessionId 'B' Constants.IvLength
            ClientToServerEncryptionKey = deriveKey sharedSecret exchangeHash sessionId 'C' Constants.AesKeyLength
            ServerToClientEncryptionKey = deriveKey sharedSecret exchangeHash sessionId 'D' Constants.AesKeyLength
            ClientToServerMacKey = deriveKey sharedSecret exchangeHash sessionId 'E' Constants.MacLength
            ServerToClientMacKey = deriveKey sharedSecret exchangeHash sessionId 'F' Constants.MacLength
        }

    // Build SSH Ed25519 public key blob
    // Format: string "ssh-ed25519" || string public_key
    let buildEd25519PublicKeyBlob (publicKey: byte[]) =
        let algorithmName = "ssh-ed25519"B
        let algorithmNameLen = BitConverter.GetBytes(uint32 algorithmName.Length)
        let publicKeyLen = BitConverter.GetBytes(uint32 publicKey.Length)
        if BitConverter.IsLittleEndian then
            Array.Reverse(algorithmNameLen)
            Array.Reverse(publicKeyLen)
        Array.concat [|
            algorithmNameLen
            algorithmName
            publicKeyLen
            publicKey
        |]

    // Build SSH RSA public key blob
    // Format: string "ssh-rsa" || mpint e || mpint n
    let buildRsaPublicKeyBlob (parameters: RSAParameters) =
        let algorithmName = "ssh-rsa"B
        let algorithmNameLen = BitConverter.GetBytes(uint32 algorithmName.Length)
        if BitConverter.IsLittleEndian then
            Array.Reverse(algorithmNameLen)

        // SSH uses big-endian integers, RSAParameters are already big-endian
        let encodeMpint (value: byte[]) =
            // Skip leading zeros but ensure we have at least one byte
            let mutable startIdx = 0
            while startIdx < value.Length - 1 && value.[startIdx] = 0uy do
                startIdx <- startIdx + 1
            let trimmed = value.[startIdx..]
            // Prepend 0x00 if MSB is set
            let needsPadding = trimmed.Length > 0 && (trimmed.[0] &&& 0x80uy) <> 0uy
            let mpint = if needsPadding then Array.append [| 0uy |] trimmed else trimmed
            let lenBytes = BitConverter.GetBytes(uint32 mpint.Length)
            if BitConverter.IsLittleEndian then
                Array.Reverse(lenBytes)
            Array.append lenBytes mpint

        let e = encodeMpint parameters.Exponent
        let n = encodeMpint parameters.Modulus

        Array.concat [|
            algorithmNameLen
            algorithmName
            e
            n
        |]

    // Build SSH Ed25519 signature blob
    // Format: string "ssh-ed25519" || string signature
    let buildEd25519SignatureBlob (signature: byte[]) =
        let algorithmName = "ssh-ed25519"B
        let algorithmNameLen = BitConverter.GetBytes(uint32 algorithmName.Length)
        let signatureLen = BitConverter.GetBytes(uint32 signature.Length)
        if BitConverter.IsLittleEndian then
            Array.Reverse(algorithmNameLen)
            Array.Reverse(signatureLen)
        Array.concat [|
            algorithmNameLen
            algorithmName
            signatureLen
            signature
        |]

    // Build SSH RSA signature blob
    let buildRsaSignatureBlob (algorithmName: string) (signature: byte[]) =
        let algorithmNameBytes = System.Text.Encoding.ASCII.GetBytes(algorithmName)
        let algorithmNameLen = BitConverter.GetBytes(uint32 algorithmNameBytes.Length)
        let signatureLen = BitConverter.GetBytes(uint32 signature.Length)
        if BitConverter.IsLittleEndian then
            Array.Reverse(algorithmNameLen)
            Array.Reverse(signatureLen)
        Array.concat [|
            algorithmNameLen
            algorithmNameBytes
            signatureLen
            signature
        |]

    // Create Ed25519 host key
    let createEd25519HostKey () =
        let (publicKey, privateKey) = generateEd25519KeyPair()
        {
            KeyType = HostKeyType.Ed25519
            PublicKeyBlob = buildEd25519PublicKeyBlob publicKey
            PrivateKey = (publicKey, privateKey) :> obj
        }

    // Create RSA host key
    let createRsaHostKey (keySizeBits: int) =
        let (_, parameters) = generateRsaKeyPair keySizeBits
        {
            KeyType = HostKeyType.Rsa
            PublicKeyBlob = buildRsaPublicKeyBlob parameters
            PrivateKey = parameters :> obj
        }

    // Sign with host key
    let signWithHostKey (hostKey: HostKey) (data: byte[]) (algorithmHint: string option) =
        match hostKey.KeyType with
        | HostKeyType.Ed25519 ->
            let (_, privateKey) = hostKey.PrivateKey :?> (byte[] * byte[])
            let signature = signEd25519 privateKey data
            buildEd25519SignatureBlob signature
        | HostKeyType.Rsa ->
            let parameters = hostKey.PrivateKey :?> RSAParameters
            let useAlgorithm = defaultArg algorithmHint Algorithms.HOSTKEY_RSA_SHA2_256
            match useAlgorithm with
            | alg when alg = Algorithms.HOSTKEY_RSA_SHA2_512 ->
                let signature = signRsaSha512 parameters data
                buildRsaSignatureBlob "rsa-sha2-512" signature
            | _ ->
                let signature = signRsaSha256 parameters data
                buildRsaSignatureBlob "rsa-sha2-256" signature

    // Parse SSH public key blob to extract algorithm name and raw key data
    let parsePublicKeyBlob (blob: byte[]) =
        if blob.Length < 4 then
            Option.None
        else
            let algorithmNameLen =
                let lenBytes = blob.[0..3]
                if BitConverter.IsLittleEndian then
                    Array.Reverse(lenBytes)
                BitConverter.ToInt32(ReadOnlySpan(lenBytes))
            if blob.Length < 4 + algorithmNameLen then
                Option.None
            else
                let algorithmName = System.Text.Encoding.ASCII.GetString(blob, 4, algorithmNameLen)
                let remainder = blob.[4 + algorithmNameLen..]
                Option.Some(algorithmName, remainder)

    // Verify a public key signature
    let verifyPublicKeySignature (publicKeyBlob: byte[]) (signatureBlob: byte[]) (data: byte[]) =
        match parsePublicKeyBlob publicKeyBlob, parsePublicKeyBlob signatureBlob with
        | Option.Some(keyAlg, keyData), Option.Some(sigAlg, sigData) ->
            // Extract actual signature from sigData (it's length-prefixed)
            if sigData.Length < 4 then
                false
            else
                let sigLen =
                    let lenBytes = sigData.[0..3]
                    if BitConverter.IsLittleEndian then
                        Array.Reverse(lenBytes)
                    BitConverter.ToInt32(ReadOnlySpan(lenBytes))
                if sigData.Length < 4 + sigLen then
                    false
                else
                    let signature = sigData.[4..4+sigLen-1]
                    match keyAlg with
                    | "ssh-ed25519" ->
                        // keyData is: uint32 length || raw_public_key (32 bytes)
                        if keyData.Length < 4 then
                            false
                        else
                            let keyLen =
                                let lenBytes = keyData.[0..3]
                                if BitConverter.IsLittleEndian then
                                    Array.Reverse(lenBytes)
                                BitConverter.ToInt32(ReadOnlySpan(lenBytes))
                            if keyData.Length < 4 + keyLen then
                                false
                            else
                                let rawKey = keyData.[4..4+keyLen-1]
                                verifyEd25519 rawKey data signature
                    | "ssh-rsa" ->
                        // Parse RSA public key: mpint e || mpint n
                        // For now, use the whole blob with RSA
                        try
                            use rsa = RSA.Create()
                            // We need to reconstruct the RSA key from e and n
                            // keyData format: uint32 e_len || e || uint32 n_len || n
                            let readMpint (mpintData: byte[]) offset =
                                let len =
                                    let lenBytes = mpintData.[offset..offset+3]
                                    if BitConverter.IsLittleEndian then
                                        Array.Reverse(lenBytes)
                                    BitConverter.ToInt32(ReadOnlySpan(lenBytes))
                                let value = mpintData.[offset+4..offset+4+len-1]
                                // Remove leading zero if present
                                let trimmed =
                                    if value.Length > 0 && value.[0] = 0uy then
                                        value.[1..]
                                    else
                                        value
                                (trimmed, offset + 4 + len)

                            let (exponent, nextOffset) = readMpint keyData 0
                            let (modulus, _) = readMpint keyData nextOffset

                            let parameters = RSAParameters(
                                Exponent = exponent,
                                Modulus = modulus
                            )
                            rsa.ImportParameters(parameters)

                            match sigAlg with
                            | "rsa-sha2-512" ->
                                rsa.VerifyData(data, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
                            | "rsa-sha2-256" ->
                                rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                            | "ssh-rsa" ->
                                rsa.VerifyData(data, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1)
                            | _ -> false
                        with _ -> false
                    | _ -> false
        | _ -> false
