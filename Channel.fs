namespace Ssh

open System
open System.Collections.Generic
open System.Net.Sockets

module Channel =

    type ChannelManager = {
        Channels: Dictionary<uint32, ChannelState>
        NextChannelId: uint32
    }

    module ChannelManager =
        let create () = {
            Channels = Dictionary<uint32, ChannelState>()
            NextChannelId = 0u
        }

        let allocateChannel (manager: ChannelManager) channelType remoteChannel remoteWindowSize remoteMaxPacketSize =
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
            ({ manager with NextChannelId = localChannel + 1u }, channel)

        let getChannel (manager: ChannelManager) channelId =
            match manager.Channels.TryGetValue(channelId) with
            | true, channel -> Some channel
            | false, _ -> None

        let updateChannel (manager: ChannelManager) channelId (update: ChannelState -> ChannelState) =
            match manager.Channels.TryGetValue(channelId) with
            | true, channel ->
                manager.Channels.[channelId] <- update channel
                true
            | false, _ -> false

        let removeChannel (manager: ChannelManager) channelId =
            manager.Channels.Remove(channelId) |> ignore

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
            if wantReply then
                let failMsg = ChannelFailure(recipientChannel)
                let! _ = Transport.sendMessage stream transportState failMsg
                ()
            return Error (ChannelError $"Unknown channel: {recipientChannel}")

        | Some channel ->
            let requestData = Packet.parseChannelRequest requestType data

            let! success = async {
                match requestData with
                | PtyReq(term, widthChars, heightRows, _, _, _) ->
                    let! result = callbacks.OnPtyRequest channel.LocalChannel term widthChars heightRows
                    if result then
                        ChannelManager.updateChannel manager recipientChannel (fun ch ->
                            { ch with PtyRequested = true; PtyTerm = Some term }
                        ) |> ignore
                    return result

                | Shell ->
                    return! callbacks.OnShellRequest channel.LocalChannel

                | Exec(command) ->
                    return! callbacks.OnExecRequest channel.LocalChannel command

                | WindowChange _ ->
                    // Window change doesn't need a callback, just acknowledge
                    return true

                | Signal _ ->
                    // Signal handling could be added
                    return true

                | _ ->
                    return false
            }

            // Return success status and remote channel for caller to send reply
            // Caller should use latest transport state to send the reply
            return Ok (transportState, manager, success, if wantReply then Some channel.RemoteChannel else None)
    }

    // Handle CHANNEL_DATA
    let handleChannelData
        (manager: ChannelManager)
        (callbacks: ChannelCallbacks)
        (recipientChannel: uint32)
        (data: byte[]) = async {

        match ChannelManager.getChannel manager recipientChannel with
        | None ->
            return Error (ChannelError $"Unknown channel: {recipientChannel}")
        | Some channel ->
            // Update window size
            let dataLen = uint32 data.Length
            ChannelManager.updateChannel manager recipientChannel (fun ch ->
                { ch with LocalWindowSize = ch.LocalWindowSize - dataLen }
            ) |> ignore

            // Notify callback
            do! callbacks.OnData channel.LocalChannel data
            return Ok manager
    }

    // Handle CHANNEL_EXTENDED_DATA
    let handleChannelExtendedData
        (manager: ChannelManager)
        (callbacks: ChannelCallbacks)
        (recipientChannel: uint32)
        (dataTypeCode: uint32)
        (data: byte[]) = async {

        match ChannelManager.getChannel manager recipientChannel with
        | None ->
            return Error (ChannelError $"Unknown channel: {recipientChannel}")
        | Some channel ->
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

        match ChannelManager.getChannel manager recipientChannel with
        | None ->
            Error (ChannelError $"Unknown channel: {recipientChannel}")
        | Some _channel ->
            ChannelManager.updateChannel manager recipientChannel (fun ch ->
                { ch with RemoteWindowSize = ch.RemoteWindowSize + bytesToAdd }
            ) |> ignore
            Ok manager

    // Send data on a channel
    let sendChannelData
        (stream: NetworkStream)
        (transportState: TransportState)
        (manager: ChannelManager)
        (localChannel: uint32)
        (data: byte[]) = async {

        match ChannelManager.getChannel manager localChannel with
        | None ->
            return Error (ChannelError $"Unknown channel: {localChannel}")
        | Some channel ->
            // Check window size
            let dataLen = uint32 data.Length
            if dataLen > channel.RemoteWindowSize then
                return Error (ChannelError "Remote window size exceeded")
            elif dataLen > channel.RemoteMaxPacketSize then
                return Error (ChannelError "Remote max packet size exceeded")
            else
                let dataMsg = ChannelData(channel.RemoteChannel, data)
                let! sendResult = Transport.sendMessage stream transportState dataMsg
                match sendResult with
                | Error e -> return Error e
                | Ok newTransportState ->
                    ChannelManager.updateChannel manager localChannel (fun ch ->
                        { ch with RemoteWindowSize = ch.RemoteWindowSize - dataLen }
                    ) |> ignore
                    return Ok newTransportState
    }

    // Send extended data (e.g., stderr) on a channel
    let sendChannelExtendedData
        (stream: NetworkStream)
        (transportState: TransportState)
        (manager: ChannelManager)
        (localChannel: uint32)
        (dataTypeCode: uint32)
        (data: byte[]) = async {

        match ChannelManager.getChannel manager localChannel with
        | None ->
            return Error (ChannelError $"Unknown channel: {localChannel}")
        | Some channel ->
            let extDataMsg = ChannelExtendedData(channel.RemoteChannel, dataTypeCode, data)
            let! sendResult = Transport.sendMessage stream transportState extDataMsg
            match sendResult with
            | Error e -> return Error e
            | Ok newTransportState ->
                return Ok newTransportState
    }

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
