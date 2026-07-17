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
    
    func drainOutputLoop() {
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
            packetFlow?.writePackets(packets, withProtocols: protocols)

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
    
    func enqueueOutbound(_ packet: Data, isIPv6: Bool) {
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
        // Weak self is deliberate here (unlike the stack's other lifetime tasks, which capture
        // strongly): `readPackets` parks until the next packet with no cancellation seam, so a strong
        // capture would pin the stack across an idle read after `stop()`. Weak self lets it deinit
        // while parked; the promoted `self` is dropped each iteration.
        readTask = Task { [weak self, packetFlow] in
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

                // Feed both sub-batches concurrently; the loop re-reads only once both finish.
                await withTaskGroup(of: Void.self) { group in
                    if !lwipBatch.isEmpty {
                        group.addTask { await self.lwipBridge.run { self.feedLwip(lwipBatch) } }
                    }
                    if !udpBatch.isEmpty {
                        group.addTask { await self.udpPlane.feed(udpBatch) }
                    }
                }
            }
        }
    }
    
    private func feedLwip(_ packets: [Data]) {
        lwipBridge.input(packets)
        // A fresh segment may have queued a timeout while the tick was suspended — re-arm.
        resumeLwipTickIfNeeded()
    }

    // MARK: - Timers
    
    func startTimeoutTimer() {
        lwipTick = lwipBridge.makeTick(
            intervalMs: TunnelConstants.lwipTimeoutIntervalMs,
            leewayMs: TunnelConstants.lwipTimeoutLeewayMs
        ) { [weak self] in
            guard let self, self.running else { return }
            if self.lwipBridge.serviceTimeouts() {
                self.suspendLwipTickIfNeeded()
            }
        }
    }
    
    private func suspendLwipTickIfNeeded() {
        lwipTick?.suspend()
    }
    
    func resumeLwipTickIfNeeded() {
        lwipTick?.resume()
    }
    
    func scheduleUDPCleanup() {
        scheduler.schedule(
            label: "udp-cleanup",
            every: TimeInterval(TunnelConstants.udpCleanupIntervalSec)
        ) { [weak self] in
            guard let self, self.running else { return }
            await self.udpPlane.cleanup()
        }
    }
}
