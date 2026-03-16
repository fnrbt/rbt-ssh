namespace Ssh

open System

/// SSH protocol message types (RFC 4253, 4252, 4254)
module MessageTypes =
    // Transport layer protocol (RFC 4253)
    [<Literal>]
    let SSH_MSG_DISCONNECT = 1uy
    [<Literal>]
    let SSH_MSG_IGNORE = 2uy
    [<Literal>]
    let SSH_MSG_UNIMPLEMENTED = 3uy
    [<Literal>]
    let SSH_MSG_DEBUG = 4uy
    [<Literal>]
    let SSH_MSG_SERVICE_REQUEST = 5uy
    [<Literal>]
    let SSH_MSG_SERVICE_ACCEPT = 6uy
    [<Literal>]
    let SSH_MSG_KEXINIT = 20uy
    [<Literal>]
    let SSH_MSG_NEWKEYS = 21uy

    // Key exchange (RFC 4253)
    [<Literal>]
    let SSH_MSG_KEX_ECDH_INIT = 30uy
    [<Literal>]
    let SSH_MSG_KEX_ECDH_REPLY = 31uy

    // User authentication (RFC 4252)
    [<Literal>]
    let SSH_MSG_USERAUTH_REQUEST = 50uy
    [<Literal>]
    let SSH_MSG_USERAUTH_FAILURE = 51uy
    [<Literal>]
    let SSH_MSG_USERAUTH_SUCCESS = 52uy
    [<Literal>]
    let SSH_MSG_USERAUTH_BANNER = 53uy
    [<Literal>]
    let SSH_MSG_USERAUTH_PK_OK = 60uy

    // Connection protocol (RFC 4254)
    [<Literal>]
    let SSH_MSG_GLOBAL_REQUEST = 80uy
    [<Literal>]
    let SSH_MSG_REQUEST_SUCCESS = 81uy
    [<Literal>]
    let SSH_MSG_REQUEST_FAILURE = 82uy
    [<Literal>]
    let SSH_MSG_CHANNEL_OPEN = 90uy
    [<Literal>]
    let SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91uy
    [<Literal>]
    let SSH_MSG_CHANNEL_OPEN_FAILURE = 92uy
    [<Literal>]
    let SSH_MSG_CHANNEL_WINDOW_ADJUST = 93uy
    [<Literal>]
    let SSH_MSG_CHANNEL_DATA = 94uy
    [<Literal>]
    let SSH_MSG_CHANNEL_EXTENDED_DATA = 95uy
    [<Literal>]
    let SSH_MSG_CHANNEL_EOF = 96uy
    [<Literal>]
    let SSH_MSG_CHANNEL_CLOSE = 97uy
    [<Literal>]
    let SSH_MSG_CHANNEL_REQUEST = 98uy
    [<Literal>]
    let SSH_MSG_CHANNEL_SUCCESS = 99uy
    [<Literal>]
    let SSH_MSG_CHANNEL_FAILURE = 100uy

/// SSH disconnect reason codes (RFC 4253)
module DisconnectReason =
    [<Literal>]
    let SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1u
    [<Literal>]
    let SSH_DISCONNECT_PROTOCOL_ERROR = 2u
    [<Literal>]
    let SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3u
    [<Literal>]
    let SSH_DISCONNECT_RESERVED = 4u
    [<Literal>]
    let SSH_DISCONNECT_MAC_ERROR = 5u
    [<Literal>]
    let SSH_DISCONNECT_COMPRESSION_ERROR = 6u
    [<Literal>]
    let SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7u
    [<Literal>]
    let SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8u
    [<Literal>]
    let SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9u
    [<Literal>]
    let SSH_DISCONNECT_CONNECTION_LOST = 10u
    [<Literal>]
    let SSH_DISCONNECT_BY_APPLICATION = 11u
    [<Literal>]
    let SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12u
    [<Literal>]
    let SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13u
    [<Literal>]
    let SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14u
    [<Literal>]
    let SSH_DISCONNECT_ILLEGAL_USER_NAME = 15u

/// Algorithm identifiers
module Algorithms =
    // Key exchange algorithms
    let KEX_CURVE25519_SHA256 = "curve25519-sha256"
    let KEX_CURVE25519_SHA256_LIBSSH = "curve25519-sha256@libssh.org"

    // Host key algorithms
    let HOSTKEY_SSH_ED25519 = "ssh-ed25519"
    let HOSTKEY_SSH_RSA = "ssh-rsa"
    let HOSTKEY_RSA_SHA2_256 = "rsa-sha2-256"
    let HOSTKEY_RSA_SHA2_512 = "rsa-sha2-512"

    // Encryption algorithms
    let CIPHER_AES256_CTR = "aes256-ctr"

    // MAC algorithms
    let MAC_HMAC_SHA2_256 = "hmac-sha2-256"

    // Compression algorithms
    let COMPRESSION_NONE = "none"

/// SSH message discriminated union
type SshMessage =
    // Transport
    | Disconnect of reason: uint32 * description: string * language: string
    | Ignore of data: byte[]
    | Unimplemented of sequenceNumber: uint32
    | Debug of alwaysDisplay: bool * message: string * language: string
    | ServiceRequest of serviceName: string
    | ServiceAccept of serviceName: string
    | KexInit of cookie: byte[] * kexAlgorithms: string list * serverHostKeyAlgorithms: string list *
                 encryptionClientToServer: string list * encryptionServerToClient: string list *
                 macClientToServer: string list * macServerToClient: string list *
                 compressionClientToServer: string list * compressionServerToClient: string list *
                 languagesClientToServer: string list * languagesServerToClient: string list *
                 firstKexPacketFollows: bool
    | NewKeys
    // Key exchange (ECDH)
    | KexEcdhInit of clientEphemeralPublicKey: byte[]
    | KexEcdhReply of hostKey: byte[] * serverEphemeralPublicKey: byte[] * signature: byte[]
    // User authentication
    | UserAuthRequest of userName: string * serviceName: string * methodName: string * methodData: AuthMethodData
    | UserAuthFailure of authMethodsThatCanContinue: string list * partialSuccess: bool
    | UserAuthSuccess
    | UserAuthBanner of message: string * language: string
    | UserAuthPkOk of algorithmName: string * publicKeyBlob: byte[]
    // Connection protocol
    | GlobalRequest of requestName: string * wantReply: bool * data: byte[]
    | RequestSuccess of data: byte[]
    | RequestFailure
    | ChannelOpen of channelType: string * senderChannel: uint32 * initialWindowSize: uint32 * maximumPacketSize: uint32 * data: byte[]
    | ChannelOpenConfirmation of recipientChannel: uint32 * senderChannel: uint32 * initialWindowSize: uint32 * maximumPacketSize: uint32 * data: byte[]
    | ChannelOpenFailure of recipientChannel: uint32 * reasonCode: uint32 * description: string * language: string
    | ChannelWindowAdjust of recipientChannel: uint32 * bytesToAdd: uint32
    | ChannelData of recipientChannel: uint32 * data: byte[]
    | ChannelExtendedData of recipientChannel: uint32 * dataTypeCode: uint32 * data: byte[]
    | ChannelEof of recipientChannel: uint32
    | ChannelClose of recipientChannel: uint32
    | ChannelRequest of recipientChannel: uint32 * requestType: string * wantReply: bool * data: byte[]
    | ChannelSuccess of recipientChannel: uint32
    | ChannelFailure of recipientChannel: uint32
    | RawMessage of messageType: byte * payload: byte[]

/// Authentication method data
and AuthMethodData =
    | NoAuth
    | Password of password: string
    | PublicKey of algorithmName: string * publicKeyBlob: byte[] * signature: byte[] option
    | HostBased of algorithmName: string * publicKeyBlob: byte[] * clientHostName: string * clientUserName: string * signature: byte[]

/// Channel request types
type ChannelRequestData =
    | PtyReq of term: string * widthChars: uint32 * heightRows: uint32 * widthPixels: uint32 * heightPixels: uint32 * modes: byte[]
    | Shell
    | Exec of command: string
    | Subsystem of name: string
    | WindowChange of widthChars: uint32 * heightRows: uint32 * widthPixels: uint32 * heightPixels: uint32
    | Signal of signalName: string
    | ExitStatus of exitStatus: uint32
    | ExitSignal of signalName: string * coreDumped: bool * errorMessage: string * language: string
    | Unknown of requestType: string * data: byte[]

/// Session state
type SessionState =
    | VersionExchange
    | KeyExchange
    | Authenticating
    | Authenticated
    | Disconnected

/// Key exchange state
type KexState = {
    ClientKexInit: byte[] option
    ServerKexInit: byte[] option
    ClientEphemeralPublic: byte[] option
    ServerEphemeralPublic: byte[] option
    ServerEphemeralPrivate: byte[] option
    SharedSecret: byte[] option
    ExchangeHash: byte[] option
    SessionId: byte[] option
}

module KexState =
    let empty = {
        ClientKexInit = None
        ServerKexInit = None
        ClientEphemeralPublic = None
        ServerEphemeralPublic = None
        ServerEphemeralPrivate = None
        SharedSecret = None
        ExchangeHash = None
        SessionId = None
    }

/// Encryption keys derived from key exchange
type DerivedKeys = {
    ClientToServerIV: byte[]
    ServerToClientIV: byte[]
    ClientToServerEncryptionKey: byte[]
    ServerToClientEncryptionKey: byte[]
    ClientToServerMacKey: byte[]
    ServerToClientMacKey: byte[]
}

/// Channel state
type ChannelState = {
    LocalChannel: uint32
    RemoteChannel: uint32
    LocalWindowSize: uint32
    RemoteWindowSize: uint32
    LocalMaxPacketSize: uint32
    RemoteMaxPacketSize: uint32
    ChannelType: string
    IsClosed: bool
    IsEof: bool
    PtyRequested: bool
    PtyTerm: string option
}

module ChannelState =
    let create localChannel remoteChannel channelType initialWindowSize maxPacketSize remoteWindowSize remoteMaxPacketSize = {
        LocalChannel = localChannel
        RemoteChannel = remoteChannel
        LocalWindowSize = initialWindowSize
        RemoteWindowSize = remoteWindowSize
        LocalMaxPacketSize = maxPacketSize
        RemoteMaxPacketSize = remoteMaxPacketSize
        ChannelType = channelType
        IsClosed = false
        IsEof = false
        PtyRequested = false
        PtyTerm = None
    }

/// Host key types
type HostKeyType =
    | Ed25519
    | Rsa

/// Host key with private key material
type HostKey = {
    KeyType: HostKeyType
    PublicKeyBlob: byte[]
    PrivateKey: obj  // NSec Key or RSA parameters
}

/// Authentication result
type AuthResult =
    | Accepted
    | Rejected
    | PartialSuccess of remainingMethods: string list

/// Connection role (determines key direction in transport)
type ConnectionRole = Server | Client

/// Host key verification policy for client connections
type HostKeyVerification =
    | AcceptAll
    | Fingerprint of expectedFingerprints: string list
    | Custom of verify: (string -> byte[] -> bool)

/// Client configuration
type ClientConfig = {
    ClientVersion: string
    Username: string
    ConnectTimeout: TimeSpan
    HostKeyVerification: HostKeyVerification
}

module ClientConfig =
    let defaults = {
        ClientVersion = "SSH-2.0-FSharpSSH_1.0"
        Username = ""
        ConnectTimeout = TimeSpan.FromSeconds(30.0)
        HostKeyVerification = AcceptAll
    }

/// SSH error types
type SshError =
    | ProtocolError of message: string
    | CryptoError of message: string
    | AuthenticationError of message: string
    | ChannelError of message: string
    | ConnectionError of message: string
    | Disconnected of reason: uint32 * description: string

/// Result type alias for SSH operations
type SshResult<'T> = Result<'T, SshError>

/// Server configuration
type ServerConfig = {
    HostKeys: HostKey list
    ServerVersion: string
    ListenPort: int
    MaxAuthAttempts: int
    AuthTimeout: TimeSpan
    IdleTimeout: TimeSpan
}

module ServerConfig =
    let defaults = {
        HostKeys = []
        ServerVersion = "SSH-2.0-FSharpSSH_1.0"
        ListenPort = 22
        MaxAuthAttempts = 6
        AuthTimeout = TimeSpan.FromSeconds(30.0)
        IdleTimeout = TimeSpan.FromMinutes(10.0)
    }

/// Authentication callbacks
type AuthCallbacks = {
    ValidatePassword: string -> string -> Async<AuthResult>
    ValidatePublicKey: string -> string -> byte[] -> Async<AuthResult>
}

/// Channel event callbacks
type ChannelCallbacks = {
    OnData: uint32 -> byte[] -> Async<unit>
    OnExtendedData: uint32 -> uint32 -> byte[] -> Async<unit>
    OnEof: uint32 -> Async<unit>
    OnClose: uint32 -> Async<unit>
    OnPtyRequest: uint32 -> string -> uint32 -> uint32 -> Async<bool>
    OnShellRequest: uint32 -> Async<bool>
    OnExecRequest: uint32 -> string -> Async<bool>
}

/// Constants
module Constants =
    [<Literal>]
    let DefaultWindowSize = 2097152u  // 2 MB
    [<Literal>]
    let DefaultMaxPacketSize = 32768u  // 32 KB
    [<Literal>]
    let MinPacketSize = 16u
    [<Literal>]
    let MaxPacketSize = 35000u
    [<Literal>]
    let BlockSize = 16  // AES block size
    [<Literal>]
    let MacLength = 32  // HMAC-SHA2-256
    [<Literal>]
    let AesKeyLength = 32  // AES-256
    [<Literal>]
    let IvLength = 16
