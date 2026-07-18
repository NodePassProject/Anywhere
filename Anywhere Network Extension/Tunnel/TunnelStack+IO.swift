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

    /// Drains the output buffer to utun. `nonisolated` and driven by ``outputDrainTask`` (a detached
    /// task), so `writePackets` runs off the lwIP queue and producers never block on it. `packetFlow`
    /// is captured at task spawn; the buffer/releases stay behind the ``outputBuffer`` Mutex, so this
    /// touches no actor-isolated state.
    nonisolated func drainOutputLoop(packetFlow: NEPacketTunnelFlow) {
        let cap = TunnelConstants.tunnelMaxPacketsPerWrite
        while true {
            var packets: [Data] = []
            var protocols: [NSNumber] = []
            var releases: [PendingRelease] = []

            outputBuffer.withLock { buffer in
                let pending = buffer.packets.count
                if pending == 0 {
                    buffer.drainInFlight = false
                    return
                }
                if pending <= cap {
                    packets = buffer.packets
                    protocols = buffer.protocols
                    releases = buffer.releases
                    buffer.packets = []
                    buffer.protocols = []
                    buffer.releases = []
                    buffer.packets.reserveCapacity(cap)
                    buffer.protocols.reserveCapacity(cap)
                    buffer.releases.reserveCapacity(cap)
                } else {
                    packets = Array(buffer.packets.prefix(cap))
                    protocols = Array(buffer.protocols.prefix(cap))
                    releases = Array(buffer.releases.prefix(cap))
                    buffer.packets.removeFirst(cap)
                    buffer.protocols.removeFirst(cap)
                    buffer.releases.removeFirst(cap)
                }
            }

            if packets.isEmpty { return }
            packetFlow.writePackets(packets, withProtocols: protocols)

            // writePackets copies into the kernel synchronously, so the buffers
            // are already unreferenced.
            if !releases.isEmpty {
                let toRelease = releases
                lwipBridge.enqueue {
                    for r in toRelease {
                        r.fn(r.ctx)
                    }
                }
            }
        }
    }

    /// Appends an outbound packet and kicks the drain if idle. `nonisolated`: called from the lwIP
    /// output callback, the off-actor read loop's reflection path, and the UDP plane.
    nonisolated func enqueueOutbound(_ packet: Data, isIPv6: Bool) {
        let proto: NSNumber = isIPv6 ? Self.ipv6Proto : Self.ipv4Proto
        let needsKick: Bool = outputBuffer.withLock { buffer in
            buffer.packets.append(packet)
            buffer.protocols.append(proto)
            buffer.releases.append(Self.noopRelease)
            if buffer.drainInFlight { return false }
            buffer.drainInFlight = true
            return true
        }
        if needsKick {
            kickOutputDrain()
        }
    }

    // MARK: - Packet Reading

    func startReadingPackets() {
        guard let packetFlow else { return }
        let plane = udpPlane!
        let bridge = lwipBridge
        // Detached so the read/partition CPU runs off the lwIP queue (like the drain). Weak self:
        // `readPackets` parks until the next packet with no cancellation seam, so a strong capture
        // would pin the stack across an idle read after `stop()`; the promoted `self` is dropped
        // each iteration. `packetFlow`/`plane`/`bridge` are captured so the loop names no isolated
        // state directly.
        readTask = Task.detached { [weak self, packetFlow, plane, bridge] in
            while !Task.isCancelled {
                let (packets, _) = await PacketFlowConcurrencyBridge.read(from: packetFlow)
                guard let self, self.running, !Task.isCancelled else { return }

                // Partition — a cheap header peek per packet. Reflected packets bounce straight
                // back into the TUN here, never reaching lwIP, UDP, routing, or the proxy.
                let reflector = self.reflector()
                var udpBatch: [Data] = []
                var lwipBatch: [Data] = []
                for packet in packets {
                    if reflector.isActive, let reflected = reflector.reflect(packet) {
                        self.enqueueOutbound(reflected.data, isIPv6: reflected.isIPv6)
                        continue
                    }
                    if let info = UDPPacket.ipProtocol(of: packet), info.proto == UDPPacket.ipProtocolUDP {
                        udpBatch.append(packet)
                    } else {
                        lwipBatch.append(packet)
                    }
                }

                // Feed both sub-batches concurrently; the loop re-reads only once both finish. The
                // lwIP feed hops onto the lwIP queue via the bridge and enters the stack's isolation
                // there through `assumeIsolated`; the UDP plane is its own actor.
                await withTaskGroup(of: Void.self) { group in
                    if !lwipBatch.isEmpty {
                        group.addTask { [lwipBatch] in
                            await bridge.run { self.assumeIsolated { $0.feedLwipBatch(lwipBatch) } }
                        }
                    }
                    if !udpBatch.isEmpty {
                        group.addTask { [udpBatch] in await plane.feed(udpBatch) }
                    }
                }
            }
        }
    }

    /// Feeds a TCP/ICMP batch into lwIP and re-arms the timeout tick. Isolated (touches
    /// ``lwipTick``); entered via `assumeIsolated` from the read loop's `lwipBridge.run` hop, so it
    /// runs on the lwIP queue.
    func feedLwipBatch(_ packets: [Data]) {
        lwipBridge.input(packets)
        // A fresh segment may have queued a timeout while the tick was suspended — re-arm.
        lwipTick?.resume()
    }

    // MARK: - Timers

    func startTimeoutTimer() {
        lwipTick = lwipBridge.makeTick(
            intervalMs: TunnelConstants.lwipTimeoutIntervalMs,
            leewayMs: TunnelConstants.lwipTimeoutLeewayMs
        ) { [weak self] in
            guard let self, self.running else { return }
            // Fires on the lwIP queue; the tick suspend is isolated state, entered via
            // `assumeIsolated` (validated against the queue, no hop).
            if self.lwipBridge.serviceTimeouts() {
                self.assumeIsolated { $0.lwipTick?.suspend() }
            }
        }
    }

    /// Re-arms the timeout tick after fresh input while stopped/suspended. Isolated; called on the
    /// lwIP queue from restart/resume paths.
    func resumeLwipTickIfNeeded() {
        lwipTick?.resume()
    }

    func scheduleUDPCleanup() {
        scheduler.schedule(
            label: "udp-cleanup",
            every: TimeInterval(TunnelConstants.udpCleanupIntervalSec)
        ) { [weak self] in
            await self?.runScheduledUDPCleanup()
        }
    }

    /// The periodic UDP-cleanup body, hopped onto the stack actor by the scheduler handler.
    private func runScheduledUDPCleanup() async {
        guard running else { return }
        await udpPlane.cleanup()
    }
}
