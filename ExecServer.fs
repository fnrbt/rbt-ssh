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

    type private ChannelReaderStream(reader: System.Threading.Channels.ChannelReader<byte[]>, ct: CancellationToken, consumed: int -> Async<SshResult<unit>>) =
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
                use linked = CancellationTokenSource.CreateLinkedTokenSource(ct, cancellationToken)
                if count = 0 then return 0
                elif completed then
                    return 0
                else
                    while offset >= current.Length && not completed do
                        try
                            let! chunk = reader.ReadAsync(linked.Token).AsTask()
                            current <- chunk
                            offset <- 0
                        with
                        | :? System.Threading.Channels.ChannelClosedException ->
                            completed <- true
                        | :? OperationCanceledException when ct.IsCancellationRequested ->
                            completed <- true

                    if completed then
                        return 0
                    else
                        let n = min count (current.Length - offset)
                        Buffer.BlockCopy(current, offset, buffer, bufferOffset, n)
                        offset <- offset + n
                        let! result = consumed n |> Async.StartAsTask
                        match result with
                        | Error e when not ct.IsCancellationRequested -> raise (IOException(sprintf "%A" e))
                        | _ -> ()
                        return n
            }

    let private sendChunks (sendOne: byte[] -> Async<SshResult<unit>>) (data: byte[]) (ct: CancellationToken) = task {
        if data.Length > 0 then
            let mutable pos = 0
            let chunkSize = 16 * 1024
            while pos < data.Length && not ct.IsCancellationRequested do
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
        (locks: SessionLocks)
        (authState: Auth.AuthState) =

        let inputs = ConcurrentDictionary<uint32, System.Threading.Channels.Channel<byte[]>>()
        let token = sessionCts.Token
        token.Register(fun () ->
            for input in inputs.Values do input.Writer.TryComplete() |> ignore) |> ignore

        let write channelId data ct =
            sendChunks
                (fun chunk -> Session.sendDataRef stream ctx locks channelId chunk ct)
                data
                ct

        let writeStderr channelId data ct =
            sendChunks
                (fun chunk -> Session.sendExtendedDataRef stream ctx locks channelId 1u chunk ct)
                data
                ct

        let exit channelId exitCode ct = task {
            let! _ = Session.closeChannelWithStatusRef stream ctx locks channelId (uint32 exitCode) |> Async.StartAsTask
            return ()
        }

        // The queue never waits on the receive loop. Its byte content is
        // bounded by the SSH window: credit is returned only by ReadAsync.
        let startExec channelId command =
            let options = System.Threading.Channels.UnboundedChannelOptions()
            options.SingleReader <- true
            options.SingleWriter <- true
            let input = System.Threading.Channels.Channel.CreateUnbounded<byte[]>(options)
            inputs.[channelId] <- input
            let manager = (!ctx).ChannelManager
            lock manager.Sync (fun () -> manager.DeferredInput.Add(channelId) |> ignore)
            let exec = {
                Username = authState.Username
                PublicKey = authState.AuthenticatedPublicKey
                ChannelId = channelId
                Command = command
                Input = new ChannelReaderStream(input.Reader, token, fun n -> Session.replenishInputRef stream ctx locks channelId (uint32 n)) :> Stream
                WriteAsync = write channelId
                WriteStderrAsync = writeStderr channelId
                ExitAsync = exit channelId
                CancellationToken = token
            }
            Task.Run(System.Func<Task>(fun () -> task {
                try
                    let! code =
                        task {
                            try
                                return! callbacks.OnExec exec
                            with ex when not token.IsCancellationRequested ->
                                let bytes = System.Text.Encoding.UTF8.GetBytes(ex.Message + "\n")
                                do! exec.WriteStderrAsync bytes token
                                return 1
                        }
                    do! exec.ExitAsync code token
                finally
                    input.Writer.TryComplete() |> ignore
                    inputs.TryRemove(channelId) |> ignore
            }), token) |> ignore

        {
            OnData = fun channelId data -> async {
                match inputs.TryGetValue(channelId) with
                | true, input when data.Length > 0 -> input.Writer.TryWrite(data) |> ignore
                | true, _ -> ()
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
        (onSessionError: exn -> unit)
        (ct: CancellationToken) = async {

        use client = client
        use stream = client.GetStream()
        use sessionCts = CancellationTokenSource.CreateLinkedTokenSource(ct)
        try
            try
                let authCallbacks = {
                    ValidatePassword = callbacks.ValidatePassword
                    ValidatePublicKey = callbacks.ValidatePublicKey
                }
                let! result =
                    Session.runSessionWithFactory
                        stream
                        config
                        authCallbacks
                        (fun stream ctx locks auth ->
                            makeChannelCallbacks callbacks sessionCts stream ctx locks auth)
                match result with
                | Ok _ -> ()
                | Error error -> onSessionError (InvalidOperationException(sprintf "%A" error))
            with
            | :? OperationCanceledException -> ()
            | ex -> onSessionError ex
        finally
            sessionCts.Cancel()
    }

    let startAsync
        (address: IPAddress)
        (port: int)
        (config: ServerConfig)
        (callbacks: ExecServerCallbacks)
        (onSessionError: exn -> unit)
        (ct: CancellationToken) = async {
        let listener = new TcpListener(address, port)
        try
            listener.Start()
            while not ct.IsCancellationRequested do
                try
                    let! client = listener.AcceptTcpClientAsync(ct).AsTask() |> Async.AwaitTask
                    Async.Start(handleClient client config callbacks onSessionError ct, ct)
                with
                | :? OperationCanceledException -> ()
                | :? ObjectDisposedException -> ()
        finally
            listener.Stop()
    }
