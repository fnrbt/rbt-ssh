namespace Rbt.Ssh

open System
open System.Collections.Generic
open System.Net.Sockets
open System.Threading

module Channel =

    type ChannelManager = {
        Channels: Dictionary<uint32, ChannelState>
        /// Channels whose ordinary data credit is returned by the consumer.
        DeferredInput: HashSet<uint32>
        NextChannelId: uint32
        /// Guards `Channels`. The receive loop mutates channel records while
        /// an exec writer reads and mutates the same records, so every access
        /// goes through this lock.
        Sync: obj
    }

    module ChannelManager =
        let create () = {
            Channels = Dictionary<uint32, ChannelState>()
            DeferredInput = HashSet<uint32>()
            NextChannelId = 0u
            Sync = obj ()
        }

        let allocateChannel (manager: ChannelManager) channelType remoteChannel remoteWindowSize remoteMaxPacketSize =
            lock manager.Sync (fun () ->
                let localChannel = manager.NextChannelId
                let channel = ChannelState.create
                                localChannel
                                remoteChannel
                                channelType
                                Constants.DefaultWindowSize
                                Constants.DefaultMaxPacketSize
                                remoteWindowSize
                                remoteMaxPacketSize
                manager.Channels.[localChannel] <- channel
                ({ manager with NextChannelId = localChannel + 1u }, channel))

        let getChannel (manager: ChannelManager) channelId =
            lock manager.Sync (fun () ->
                match manager.Channels.TryGetValue(channelId) with
                | true, channel -> Some channel
                | false, _ -> None)

        let updateChannel (manager: ChannelManager) channelId (update: ChannelState -> ChannelState) =
            lock manager.Sync (fun () ->
                match manager.Channels.TryGetValue(channelId) with
                | true, channel ->
                    let updated = update channel
                    manager.Channels.[channelId] <- updated
                    if updated.IsClosed && not channel.IsClosed then
                        channel.WindowSignal.TrySetResult () |> ignore
                    true
                | false, _ -> false)

        let removeChannel (manager: ChannelManager) channelId =
            lock manager.Sync (fun () ->
                match manager.Channels.TryGetValue(channelId) with
                | true, channel ->
                    // Release any sender waiting for credit on this channel.
                    channel.WindowSignal.TrySetResult () |> ignore
                | false, _ -> ()
                manager.DeferredInput.Remove(channelId) |> ignore
                manager.Channels.Remove(channelId) |> ignore)

    /// Outcome of asking to send `requested` bytes of channel data.
    type CreditGrant =
        /// Credit is reserved for these bytes; they may be sent now.
        | Granted of bytes: byte[]
        /// The peer window is empty. Await the signal, then ask again. The
        /// reservation is not taken, so the caller must not send anything.
        | Waiting of signal: System.Threading.Tasks.TaskCompletionSource<unit>

    /// Reserve up to one packet of outbound credit, or report the signal that
    /// announces the next CHANNEL_WINDOW_ADJUST. Checking the window and
    /// capturing the signal happen under one lock hold, so an adjustment that
    /// lands between the two can never be missed. Only the granted segment
    /// starting at `offset` is copied, never the unsent remainder.
    let acquireOutboundCredit
        (manager: ChannelManager)
        (localChannel: uint32)
        (data: byte[])
        (offset: int) =
        lock manager.Sync (fun () ->
            match manager.Channels.TryGetValue(localChannel) with
            | false, _ -> Error (ChannelError $"Unknown channel: {localChannel}")
            | true, channel when channel.IsClosed -> Error (ChannelError $"Channel is closed: {localChannel}")
            | true, _ when offset < 0 || offset >= data.Length ->
                Error (ChannelError "Outbound data offset is outside the buffer")
            | true, channel ->
                let packetLimit = min (uint32 (data.Length - offset)) channel.RemoteMaxPacketSize
                if channel.RemoteWindowSize = 0u || packetLimit = 0u then
                    Ok (Waiting channel.WindowSignal)
                else
                    let granted = min packetLimit channel.RemoteWindowSize
                    manager.Channels.[localChannel] <-
                        { channel with RemoteWindowSize = channel.RemoteWindowSize - granted }
                    Ok (Granted data.[offset .. offset + int granted - 1]))

    /// Await an outbound credit signal. Returns an error if the send is
    /// cancelled while waiting.
    let waitForCredit
        (signal: System.Threading.Tasks.TaskCompletionSource<unit>)
        (ct: CancellationToken) = async {
        return!
            task {
                try
                    do! signal.Task.WaitAsync(ct)
                    return Ok ()
                with :? OperationCanceledException ->
                    return Error (ChannelError "Channel send cancelled")
            } |> Async.AwaitTask
    }

    // Handle CHANNEL_OPEN request
    let handleChannelOpen
        (stream: NetworkStream)
        (transportState: TransportState)
        (manager: ChannelManager)
        (channelType: string)
        (senderChannel: uint32)
        (initialWindowSize: uint32)
        (maximumPacketSize: uint32)
        (_data: byte[]) = async {

        match channelType with
        | "session" ->
            // Allocate a new channel
            let (newManager, channel) = ChannelManager.allocateChannel
                                            manager
                                            channelType
                                            senderChannel
                                            initialWindowSize
                                            maximumPacketSize

            // Send confirmation
            let confirmMsg = ChannelOpenConfirmation(
                senderChannel,
                channel.LocalChannel,
                channel.LocalWindowSize,
                channel.LocalMaxPacketSize,
                [||]
            )

            let! sendResult = Transport.sendMessage stream transportState confirmMsg
            match sendResult with
            | Error e -> return Error e
            | Ok newTransportState ->
                return Ok (newTransportState, newManager, Some channel)

        | _ ->
            // Unknown channel type, reject
            let failMsg = ChannelOpenFailure(
                senderChannel,
                3u,  // SSH_OPEN_UNKNOWN_CHANNEL_TYPE
                $"Unknown channel type: {channelType}",
                ""
            )
            let! sendResult = Transport.sendMessage stream transportState failMsg
            match sendResult with
            | Error e -> return Error e
            | Ok newTransportState ->
                return Ok (newTransportState, manager, None)
    }

    // Handle CHANNEL_REQUEST
    let handleChannelRequest
        (stream: NetworkStream)
        (transportState: TransportState)
        (manager: ChannelManager)
        (callbacks: ChannelCallbacks)
        (recipientChannel: uint32)
        (requestType: string)
        (wantReply: bool)
        (data: byte[]) = async {

        match ChannelManager.getChannel manager recipientChannel with
        | None ->
            // No valid remote channel exists for a failure reply.
            return Error (ChannelError $"Unknown channel: {recipientChannel}")

        | Some channel ->
            let parsed =
                try Ok (Packet.parseChannelRequest requestType data)
                with :? ArgumentException as error -> Error (ProtocolError error.Message)
            match parsed with
            | Error error -> return Error error
            | Ok requestData ->
                let! success = async {
                    match requestData with
                    | PtyReq(term, widthChars, heightRows, _, _, _) ->
                        let! result = callbacks.OnPtyRequest channel.LocalChannel term widthChars heightRows
                        if result then
                            ChannelManager.updateChannel manager recipientChannel (fun ch ->
                                { ch with PtyRequested = true; PtyTerm = Some term }
                            ) |> ignore
                        return result

                    | Shell when not channel.ProgramStarted ->
                        let! result = callbacks.OnShellRequest channel.LocalChannel
                        if result then
                            ChannelManager.updateChannel manager recipientChannel (fun ch -> { ch with ProgramStarted = true }) |> ignore
                        return result

                    | Exec(command) when not channel.ProgramStarted ->
                        let! result = callbacks.OnExecRequest channel.LocalChannel command
                        if result then
                            ChannelManager.updateChannel manager recipientChannel (fun ch -> { ch with ProgramStarted = true }) |> ignore
                        return result

                    | WindowChange _ ->
                        // Window change doesn't need a callback, just acknowledge
                        return true

                    | Signal _ ->
                        // Signal handling could be added
                        return true

                    | _ ->
                        return false
                }

                // Caller sends the reply using its latest transport state.
                return Ok (transportState, manager, success, if wantReply then Some channel.RemoteChannel else None)
    }

    /// Debit the shared receive window before delivering either data form.
    let private debitInbound (manager: ChannelManager) recipientChannel (length: int) =
        lock manager.Sync (fun () ->
            match manager.Channels.TryGetValue recipientChannel with
            | false, _ -> Error (ChannelError $"Unknown channel: {recipientChannel}")
            | true, channel when length < 0 || uint64 length > uint64 channel.LocalWindowSize ||
                                 uint64 length > uint64 channel.LocalMaxPacketSize ->
                Error (ProtocolError "Channel data exceeds receive window or maximum packet size")
            | true, channel ->
                manager.Channels.[recipientChannel] <- { channel with LocalWindowSize = channel.LocalWindowSize - uint32 length }
                Ok channel)

    /// Validate and reserve receive credit for ordinary or extended data.
    let receiveDataCredit manager recipientChannel length : SshResult<unit> =
        debitInbound manager recipientChannel length |> Result.map ignore

    let handleChannelData
        (manager: ChannelManager)
        (callbacks: ChannelCallbacks)
        (recipientChannel: uint32)
        (data: byte[]) = async {
        match debitInbound manager recipientChannel data.Length with
        | Error e -> return Error e
        | Ok channel ->
            do! callbacks.OnData channel.LocalChannel data
            return Ok manager
    }

    let handleChannelExtendedData
        (manager: ChannelManager)
        (callbacks: ChannelCallbacks)
        (recipientChannel: uint32)
        (dataTypeCode: uint32)
        (data: byte[]) = async {
        match debitInbound manager recipientChannel data.Length with
        | Error e -> return Error e
        | Ok channel ->
            do! callbacks.OnExtendedData channel.LocalChannel dataTypeCode data
            return Ok manager
    }

    // Handle CHANNEL_EOF
    let handleChannelEof
        (manager: ChannelManager)
        (callbacks: ChannelCallbacks)
        (recipientChannel: uint32) = async {

        match ChannelManager.getChannel manager recipientChannel with
        | None ->
            return Error (ChannelError $"Unknown channel: {recipientChannel}")
        | Some channel ->
            ChannelManager.updateChannel manager recipientChannel (fun ch ->
                { ch with IsEof = true }
            ) |> ignore
            do! callbacks.OnEof channel.LocalChannel
            return Ok manager
    }

    // Handle CHANNEL_CLOSE
    let handleChannelClose
        (stream: NetworkStream)
        (transportState: TransportState)
        (manager: ChannelManager)
        (callbacks: ChannelCallbacks)
        (recipientChannel: uint32) = async {

        match ChannelManager.getChannel manager recipientChannel with
        | None ->
            return Ok (transportState, manager)
        | Some channel ->
            // Send close back if we haven't already
            let! newTransportState =
                if not channel.IsClosed then
                    async {
                        let closeMsg = ChannelClose(channel.RemoteChannel)
                        let! sendResult = Transport.sendMessage stream transportState closeMsg
                        match sendResult with
                        | Ok state -> return state
                        | Error _ -> return transportState
                    }
                else
                    async {
                        return transportState
                    }

            do! callbacks.OnClose channel.LocalChannel
            ChannelManager.removeChannel manager recipientChannel
            return Ok (newTransportState, manager)
    }

    // Handle CHANNEL_WINDOW_ADJUST
    let handleWindowAdjust
        (manager: ChannelManager)
        (recipientChannel: uint32)
        (bytesToAdd: uint32) =

        lock manager.Sync (fun () ->
            match manager.Channels.TryGetValue(recipientChannel) with
            | false, _ -> Error (ChannelError $"Unknown channel: {recipientChannel}")
            | true, channel ->
                // Replace the signal before granting credit so a sender that
                // missed this adjustment waits for the next one.
                channel.WindowSignal.TrySetResult () |> ignore
                manager.Channels.[recipientChannel] <-
                    { channel with
                        RemoteWindowSize = channel.RemoteWindowSize + bytesToAdd
                        WindowSignal =
                            System.Threading.Tasks.TaskCompletionSource<unit>(
                                System.Threading.Tasks.TaskCreationOptions.RunContinuationsAsynchronously) }
                Ok manager)

    // Send EOF on a channel
    let sendChannelEof
        (stream: NetworkStream)
        (transportState: TransportState)
        (manager: ChannelManager)
        (localChannel: uint32) = async {

        match ChannelManager.getChannel manager localChannel with
        | None ->
            return Error (ChannelError $"Unknown channel: {localChannel}")
        | Some channel ->
            let eofMsg = ChannelEof(channel.RemoteChannel)
            let! sendResult = Transport.sendMessage stream transportState eofMsg
            match sendResult with
            | Error e -> return Error e
            | Ok newTransportState ->
                return Ok newTransportState
    }

    // Close a channel
    let closeChannel
        (stream: NetworkStream)
        (transportState: TransportState)
        (manager: ChannelManager)
        (localChannel: uint32) = async {

        match ChannelManager.getChannel manager localChannel with
        | None ->
            return Error (ChannelError $"Unknown channel: {localChannel}")
        | Some channel ->
            ChannelManager.updateChannel manager localChannel (fun ch ->
                { ch with IsClosed = true }
            ) |> ignore

            let closeMsg = ChannelClose(channel.RemoteChannel)
            let! sendResult = Transport.sendMessage stream transportState closeMsg
            match sendResult with
            | Error e -> return Error e
            | Ok newTransportState ->
                return Ok newTransportState
    }

    // Send exit status on a channel
    let sendExitStatus
        (stream: NetworkStream)
        (transportState: TransportState)
        (manager: ChannelManager)
        (localChannel: uint32)
        (exitStatus: uint32) = async {

        match ChannelManager.getChannel manager localChannel with
        | None ->
            return Error (ChannelError $"Unknown channel: {localChannel}")
        | Some channel ->
            let requestData = Packet.buildChannelRequestData (ExitStatus(exitStatus))
            let requestMsg = ChannelRequest(channel.RemoteChannel, "exit-status", false, requestData)
            let! sendResult = Transport.sendMessage stream transportState requestMsg
            match sendResult with
            | Error e -> return Error e
            | Ok newTransportState ->
                return Ok newTransportState
    }

    // Send window adjust
    let sendWindowAdjust
        (stream: NetworkStream)
        (transportState: TransportState)
        (manager: ChannelManager)
        (localChannel: uint32)
        (bytesToAdd: uint32) = async {

        match ChannelManager.getChannel manager localChannel with
        | None ->
            return Error (ChannelError $"Unknown channel: {localChannel}")
        | Some channel ->
            ChannelManager.updateChannel manager localChannel (fun ch ->
                { ch with LocalWindowSize = ch.LocalWindowSize + bytesToAdd }
            ) |> ignore

            let adjustMsg = ChannelWindowAdjust(channel.RemoteChannel, bytesToAdd)
            let! sendResult = Transport.sendMessage stream transportState adjustMsg
            match sendResult with
            | Error e -> return Error e
            | Ok newTransportState ->
                return Ok newTransportState
    }
