//
//  TunnelStack+IO.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import NetworkExtension
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "TunnelStack+IO")

extension TunnelStack {

    // MARK: - Output Batching
    
    nonisolated func drainOutputLoop(packetFlow: NEPacketTunnelFlow) async {
        while true {
            var packets: [Data] = []
            var protocols: [NSNumber] = []
            var releases: [LWIPReleaseAction] = []

            outputBuffer.withLock { buffer in
                let pending = buffer.packets.count
                if pending == 0 {
                    buffer.drainInFlight = false
                    return
                }
                packets = buffer.packets
                protocols = buffer.protocols
                releases = buffer.releases
                buffer.packets = []
                buffer.protocols = []
                buffer.releases = []
            }

            if packets.isEmpty { return }
            packetFlow.writePackets(packets, withProtocols: protocols)
            
            if !releases.isEmpty {
                let toRelease = releases
                lwipBridge.enqueue {
                    for release in toRelease {
                        release.run()
                    }
                }
            }

            await Task.yield()
        }
    }
    
    nonisolated func enqueueOutbound(_ packet: Data, isIPv6: Bool) {
        let proto: NSNumber = isIPv6 ? Self.ipv6Proto : Self.ipv4Proto
        let needsKick: Bool = outputBuffer.withLock { buffer in
            buffer.packets.append(packet)
            buffer.protocols.append(proto)
            buffer.releases.append(.noop)
            if buffer.drainInFlight { return false }
            buffer.drainInFlight = true
            return true
        }
        if needsKick {
            kickOutputDrain()
        }
    }

    // MARK: - Packet Reading

    /// Duty-cycle child: feeds each inbound TUN batch to lwIP + the UDP plane. The raw
    /// `readPackets()` await never resumes on cancellation, so the tree must not await it
    /// directly — ``stop()`` would hang on a quiet utun. An unstructured producer (the same
    /// border pattern as ``PathMonitorConcurrencyBridge``) owns that await, paced by a demand
    /// token so utun still paces us: the next read starts only after the previous batch is
    /// processed. Cancelling this child ends the batch stream at once; the orphaned producer dies
    /// at its next resume, its late yield landing in a terminated stream, not a shut-down engine.
    func runReadLoop(packetFlow: NEPacketTunnelFlow, udpPlane: UDPPlane) async {
        let demand = AsyncInbox<Void>(capacity: 1)
        demand.yield(())
        let batches = AsyncStream<[Data]> { continuation in
            let producer = Task {
                while (try? await demand.next()) != nil {
                    let (packets, _) = await packetFlow.readPackets()
                    continuation.yield(packets)
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in producer.cancel() }
        }
        for await packets in batches {
            await processInboundBatch(packets, udpPlane: udpPlane)
            demand.yield(())
        }
    }

    /// Partitions one inbound batch on the actor and feeds both sub-batches; the next read waits
    /// on both.
    private func processInboundBatch(_ packets: [Data], udpPlane: UDPPlane) async {
        let reflector = reflector()
        var lwipBatch: [Data] = []
        var udpBatch: [Data] = []

        for packet in packets {
            if reflector.isActive, let reflected = reflector.reflect(packet) {
                enqueueOutbound(reflected.data, isIPv6: reflected.isIPv6)
                continue
            }
            if UDPPacket.ipProtocol(of: packet)?.proto == UDPPacket.ipProtocolUDP {
                udpBatch.append(packet)
            } else {
                lwipBatch.append(packet)
            }
        }

        await withTaskGroup(of: Void.self) { group in
            group.addTask { [lwipBatch] in
                await self.lwipBridge.run { self.assumeIsolated { $0.feedLwipBatch(lwipBatch) } }
            }
            group.addTask { [udpBatch] in await udpPlane.feed(udpBatch) }
        }
    }
    
    func feedLwipBatch(_ packets: [Data]) {
        lwipBridge.input(packets)
        lwipTick?.resume()
    }

    // MARK: - Timers

    func startTimeoutTimer() {
        lwipTick = lwipBridge.makeTick(
            intervalMs: TunnelConstants.lwipTimeoutIntervalMs,
            leewayMs: TunnelConstants.lwipTimeoutLeewayMs
        ) { [weak self] in
            guard let self, self.running else { return }
            if self.lwipBridge.serviceTimeouts() {
                self.assumeIsolated { $0.lwipTick?.suspend() }
            }
        }
    }
    
    func resumeLwipTickIfNeeded() {
        lwipTick?.resume()
    }

    /// Duty-cycle child, replacing the former `TunnelScheduler`: reaps idle UDP flows every
    /// ``TunnelConstants/udpCleanupIntervalSec``. ``TunnelStack/udpCleanupPoke`` (fed on device
    /// wake) breaks the sleep so an interval that fell due while the clock was frozen fires
    /// promptly instead of drifting; an early poke just re-sleeps the remainder.
    nonisolated func runUDPCleanupLoop(udpPlane: UDPPlane) async {
        let interval = TimeInterval(TunnelConstants.udpCleanupIntervalSec)
        var lastRun = MonotonicClock.now
        while !Task.isCancelled {
            let remaining = interval - (MonotonicClock.now - lastRun)
            if remaining > 0 {
                await sleepOrWakePoke(seconds: remaining)
                continue
            }
            if running {
                await udpPlane.cleanup()
            }
            lastRun = MonotonicClock.now
        }
    }

    /// Parks until `seconds` elapse or a device-wake poke arrives, whichever comes first.
    private nonisolated func sleepOrWakePoke(seconds: TimeInterval) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                try? await Task.sleep(for: .seconds(seconds))
            }
            group.addTask { _ = try? await self.udpCleanupPoke.next() }
            _ = await group.next()
            group.cancelAll()
        }
    }
}
