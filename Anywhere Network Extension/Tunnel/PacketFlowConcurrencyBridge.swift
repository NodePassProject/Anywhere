//
//  PacketFlowConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import NetworkExtension

nonisolated enum PacketFlowConcurrencyBridge {

    /// One TUN read: resumes with the next inbound batch, or `nil` once the awaiting task is
    /// cancelled. `readPackets` itself has no cancellation seam — a parked read may complete long
    /// after (or never, on a stopped tunnel). The one-shot stream supplies the missing seam: its
    /// iteration ends on task cancellation, and a late completion yields into the finished stream
    /// and is dropped, pinning nothing but `flow`. This is what lets the read loop capture its
    /// resources strongly and rely on plain cancellation for teardown.
    static func read(from flow: NEPacketTunnelFlow) async -> (packets: [Data], protocols: [NSNumber])? {
        let (stream, continuation) = AsyncStream.makeStream(
            of: (packets: [Data], protocols: [NSNumber]).self,
            bufferingPolicy: .bufferingNewest(1)
        )
        flow.readPackets { packets, protocols in
            continuation.yield((packets: packets, protocols: protocols))
            continuation.finish()
        }
        for await batch in stream { return batch }
        return nil
    }
}
