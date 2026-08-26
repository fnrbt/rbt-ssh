namespace Rbt.Ssh

open System
open System.Collections.Concurrent
open System.IO
open System.Net
open System.Net.Sockets
open System.Threading
open System.Threading.Tasks

type ExecChannel = {
    Username: string option
    PublicKey: (string * byte[]) option
    ChannelId: uint32
    Command: string
    Input: Stream
    WriteAsync: byte[] -> CancellationToken -> Task<unit>
    WriteStderrAsync: byte[] -> CancellationToken -> Task<unit>
    ExitAsync: int -> CancellationToken -> Task<unit>
    CancellationToken: CancellationToken
}

type ExecServerCallbacks = {
    ValidatePassword: string -> string -> Async<AuthResult>
    ValidatePublicKey: string -> string -> byte[] -> Async<AuthResult>
    OnExec: ExecChannel -> Task<int>
}

module ExecServer =

    type private ChannelReaderStream(reader: System.Threading.Channels.ChannelReader<byte[]>, ct: CancellationToken) =
        inherit Stream()

        let mutable current = Array.empty<byte>
        let mutable offset = 0
        let mutable completed = false

        override _.CanRead = true
        override _.CanSeek = false
        override _.CanWrite = false
        override _.Length = raise (NotSupportedException())
        override _.Position
            with get () = raise (NotSupportedException())
            and set _ = raise (NotSupportedException())

        override _.Flush() = ()
        override _.Seek(_, _) = raise (NotSupportedException())
        override _.SetLength(_) = raise (NotSupportedException())
        override _.Write(_, _, _) = raise (NotSupportedException())

        override this.Read(buffer: byte[], bufferOffset: int, count: int) =
            this.ReadAsync(buffer, bufferOffset, count, ct).GetAwaiter().GetResult()

        override _.ReadAsync(buffer: byte[], bufferOffset: int, count: int, cancellationToken: CancellationToken) =
            task {
                if completed then
                    return 0
                else
                    while offset >= current.Length && not completed do
                        try
                            let! chunk = reader.ReadAsync(cancellationToken).AsTask()
                            current <- chunk
                            offset <- 0
                        with
                        | :? System.Threading.Channels.ChannelClosedException ->
                            completed <- true
                        | :? OperationCanceledException ->
                            completed <- true

                    if completed then
                        return 0
                    else
                        let n = min count (current.Length - offset)
                        Buffer.BlockCopy(current, offset, buffer, bufferOffset, n)
                        offset <- offset + n
                        return n
            }

    let private sendChunks (sendOne: byte[] -> Async<SshResult<unit>>) (data: byte[]) (_ct: CancellationToken) = task {
        if data.Length > 0 then
            let mutable pos = 0
            let chunkSize = 16 * 1024
            while pos < data.Length do
                let n = min chunkSize (data.Length - pos)
                let chunk = Array.zeroCreate<byte> n
                Buffer.BlockCopy(data, pos, chunk, 0, n)
                let! result = sendOne chunk |> Async.StartAsTask
                match result with
                | Error e -> raise (InvalidOperationException(sprintf "%A" e))
                | Ok () -> pos <- pos + n
    }

    let private makeChannelCallbacks
        (callbacks: ExecServerCallbacks)
        (sessionCts: CancellationTokenSource)
        (stream: NetworkStream)
        (ctx: SessionContext ref)
        (sendLock: SemaphoreSlim)
        (authState: Auth.AuthState) =

        let inputs = ConcurrentDictionary<uint32, System.Threading.Channels.Channel<byte[]>>()
        let token = sessionCts.Token

        let write channelId data ct =
            sendChunks
                (fun chunk -> Session.sendDataRef stream ctx sendLock channelId chunk)
                data
                ct

        let writeStderr channelId data ct =
            sendChunks
                (fun chunk -> Session.sendExtendedDataRef stream ctx sendLock channelId 1u chunk)
                data
                ct

        let exit channelId exitCode ct = task {
            let! _ = Session.closeChannelWithStatusRef stream ctx sendLock channelId (uint32 exitCode) |> Async.StartAsTask
            return ()
        }

        let startExec channelId command =
            let options = System.Threading.Channels.UnboundedChannelOptions()
            options.SingleReader <- true
            options.SingleWriter <- false
            let input = System.Threading.Channels.Channel.CreateUnbounded<byte[]>(options)
            inputs.[channelId] <- input
            let exec = {
                Username = authState.Username
                PublicKey = authState.AuthenticatedPublicKey
                ChannelId = channelId
                Command = command
                Input = new ChannelReaderStream(input.Reader, token) :> Stream
                WriteAsync = write channelId
                WriteStderrAsync = writeStderr channelId
                ExitAsync = exit channelId
                CancellationToken = token
            }
            Task.Run(System.Func<Task>(fun () -> task {
                let! code =
                    task {
                        try
                            return! callbacks.OnExec exec
                        with ex ->
                            let bytes = System.Text.Encoding.UTF8.GetBytes(ex.Message + "\n")
                            do! exec.WriteStderrAsync bytes token
                            return 1
                    }
                do! exec.ExitAsync code token
                input.Writer.TryComplete() |> ignore
            }), token) |> ignore

        {
            OnData = fun channelId data -> async {
                match inputs.TryGetValue(channelId) with
                | true, input -> input.Writer.TryWrite(data) |> ignore
                | false, _ -> ()
            }
            OnExtendedData = fun _ _ _ -> async { () }
            OnEof = fun channelId -> async {
                match inputs.TryGetValue(channelId) with
                | true, input -> input.Writer.TryComplete() |> ignore
                | false, _ -> ()
            }
            OnClose = fun channelId -> async {
                match inputs.TryRemove(channelId) with
                | true, input -> input.Writer.TryComplete() |> ignore
                | false, _ -> ()
            }
            OnPtyRequest = fun _ _ _ _ -> async { return false }
            OnShellRequest = fun _ -> async { return false }
            OnExecRequest = fun channelId command -> async {
                startExec channelId command
                return true
            }
        }

    let handleClient
        (client: TcpClient)
        (config: ServerConfig)
        (callbacks: ExecServerCallbacks)
        (ct: CancellationToken) = async {

        use client = client
        use stream = client.GetStream()
        use sessionCts = CancellationTokenSource.CreateLinkedTokenSource(ct)
        try
            let authCallbacks = {
                ValidatePassword = callbacks.ValidatePassword
                ValidatePublicKey = callbacks.ValidatePublicKey
            }
            let! _ =
                Session.runSessionWithFactory
                    stream
                    config
                    authCallbacks
                    (fun stream ctx sendLock auth ->
                        makeChannelCallbacks callbacks sessionCts stream ctx sendLock auth)
            return ()
        with
        | :? OperationCanceledException -> ()
        | _ -> ()
    }

    let startAsync
        (address: IPAddress)
        (port: int)
        (config: ServerConfig)
        (callbacks: ExecServerCallbacks)
        (ct: CancellationToken) = async {
        let listener = new TcpListener(address, port)
        try
            listener.Start()
            while not ct.IsCancellationRequested do
                try
                    let! client = listener.AcceptTcpClientAsync(ct).AsTask() |> Async.AwaitTask
                    Async.Start(handleClient client config callbacks ct, ct)
                with
                | :? OperationCanceledException -> ()
                | :? ObjectDisposedException -> ()
        finally
            listener.Stop()
    }
