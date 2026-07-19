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

    func startReadingPackets() {
        guard let packetFlow else { return }
        let plane = udpPlane!
        let bridge = lwipBridge
        readTask = Task.detached { [self, packetFlow, plane, bridge] in
            while !Task.isCancelled {
                guard let (packets, _) = await PacketFlowConcurrencyBridge.read(from: packetFlow),
                      running, !Task.isCancelled else { return }
                
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
                
                if udpBatch.isEmpty {
                    if !lwipBatch.isEmpty {
                        await bridge.run { self.assumeIsolated { $0.feedLwipBatch(lwipBatch) } }
                    }
                } else if lwipBatch.isEmpty {
                    await plane.feed(udpBatch)
                } else {
                    await withTaskGroup(of: Void.self) { group in
                        group.addTask { [lwipBatch] in
                            await bridge.run { self.assumeIsolated { $0.feedLwipBatch(lwipBatch) } }
                        }
                        group.addTask { [udpBatch] in await plane.feed(udpBatch) }
                    }
                }
            }
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

    func scheduleUDPCleanup() {
        scheduler.schedule(
            label: "udp-cleanup",
            every: TimeInterval(TunnelConstants.udpCleanupIntervalSec)
        ) { [weak self] in
            await self?.runScheduledUDPCleanup()
        }
    }
    
    private func runScheduledUDPCleanup() async {
        guard running else { return }
        await udpPlane.cleanup()
    }
}
