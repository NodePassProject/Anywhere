//
//  TunnelStack+IO.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import NetworkExtension

private let logger = AnywhereLogger(category: "TunnelStack+IO")

extension TunnelStack {

    // MARK: - Output Batching
    //
    // Two producers append under ``outputBufferLock`` (lwIP callbacks on
    // ``lwipQueue``, Swift UDP/ICMP builders on ``udpQueue``); the appender
    // that finds no drain in flight kicks one ``drainOutputLoop`` on
    // ``outputQueue``. Per-packet pbuf/heap releases still fire on ``lwipQueue``.

    /// Drains the output buffer with back-to-back writePackets calls, each
    /// capped at tunnelMaxPacketsPerWrite (utun's empirical per-call ceiling —
    /// exceeding it trips ENOSPC). ``outputDrainInFlight`` flips back false
    /// under the lock, atomic with the empty check, so a concurrent appender
    /// can't see "drain in flight" after the loop has decided to exit.
    func drainOutputLoop() {
        let cap = TunnelConstants.tunnelMaxPacketsPerWrite
        while true {
            var packets: [Data] = []
            var protocols: [NSNumber] = []
            var releases: [PendingRelease] = []

            var queueDepth = 0
            outputBufferLock.withLock {
                let pending = outputPackets.count
                queueDepth = pending
                if pending == 0 {
                    outputDrainInFlight = false
                    return
                }
                if pending <= cap {
                    packets = outputPackets
                    protocols = outputProtocols
                    releases = pendingReleases
                    outputPackets = []
                    outputProtocols = []
                    pendingReleases = []
                    outputPackets.reserveCapacity(cap)
                    outputProtocols.reserveCapacity(cap)
                    pendingReleases.reserveCapacity(cap)
                } else {
                    packets = Array(outputPackets.prefix(cap))
                    protocols = Array(outputProtocols.prefix(cap))
                    releases = Array(pendingReleases.prefix(cap))
                    outputPackets.removeFirst(cap)
                    outputProtocols.removeFirst(cap)
                    pendingReleases.removeFirst(cap)
                }
            }
            
            PerformanceMonitor.gauge(.outputQueueDepth, queueDepth, highWater: TunnelConstants.tunnelMaxPacketsPerWrite * 4)
            if packets.isEmpty { return }
            packetFlow?.writePackets(packets, withProtocols: protocols)

            // writePackets copies into the kernel synchronously, so the buffers
            // are already unreferenced.
            if !releases.isEmpty {
                lwipQueue.async {
                    for r in releases {
                        r.fn(r.ctx)
                    }
                }
            }
        }
    }

    /// Appends a Swift-built IP packet to the output buffer and kicks the drain
    /// if idle; ``noopRelease`` keeps ``pendingReleases`` index-aligned.
    func enqueueOutbound(_ packet: Data, isIPv6: Bool) {
        let proto: NSNumber = isIPv6 ? Self.ipv6Proto : Self.ipv4Proto
        let needsKick: Bool = outputBufferLock.withLock {
            outputPackets.append(packet)
            outputProtocols.append(proto)
            pendingReleases.append(Self.noopRelease)
            if outputDrainInFlight { return false }
            outputDrainInFlight = true
            return true
        }
        if needsKick {
            outputQueue.async { [self] in drainOutputLoop() }
        }
    }

    // MARK: - Packet Reading

    /// Continuously reads IP packets from the tunnel, splitting each batch:
    /// UDP datagrams to ``udpQueue``, TCP/ICMP into lwIP on ``lwipQueue``.
    /// Backpressure: the next read is issued only after *both* sub-batches
    /// finish, so at most one batch is ever in flight (utun paces us).
    func startReadingPackets() {
        packetFlow?.readPackets { [weak self] packets, _ in
            guard let self, self.running else { return }

            // Partition on the read-callback thread — a cheap header peek per
            // packet. Reflected packets bounce straight back into the TUN here,
            // never reaching lwIP, UDP, routing, or the proxy.
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

            switch (lwipBatch.isEmpty, udpBatch.isEmpty) {
            case (true, true):
                // Empty or all-reflected batch — re-arm so the loop can't stall.
                self.startReadingPackets()
            case (false, true):
                self.lwipQueue.async {
                    self.feedLwip(lwipBatch)
                    self.startReadingPackets()
                }
            case (true, false):
                self.udpQueue.async {
                    self.feedUDP(udpBatch)
                    self.startReadingPackets()
                }
            case (false, false):
                let group = DispatchGroup()
                group.enter()
                self.lwipQueue.async { self.feedLwip(lwipBatch); group.leave() }
                group.enter()
                self.udpQueue.async { self.feedUDP(udpBatch); group.leave() }
                // Re-arm off the data-plane queues so the next read waits only
                // on both finishing, not on either queue's depth.
                group.notify(queue: DispatchQueue.global(qos: .userInitiated)) { [weak self] in
                    self?.startReadingPackets()
                }
            }
        }
    }

    /// Feeds a TCP/ICMP sub-batch into lwIP. Must run on ``lwipQueue``. The
    /// batch bracket coalesces per-segment ACKs and walks every active PCB on `_end`.
    private func feedLwip(_ packets: [Data]) {
        lwip_bridge_input_batch_begin()
        for packet in packets {
            packet.withUnsafeBytes { buffer in
                guard let baseAddress = buffer.baseAddress else { return }
                lwip_bridge_input(baseAddress, Int32(buffer.count))
            }
        }
        lwip_bridge_input_batch_end()
        // A fresh segment may have queued a timeout while the tick was suspended — re-arm.
        resumeLwipTickIfNeeded()
    }

    /// Parses and dispatches a UDP sub-batch. Must run on ``udpQueue``.
    private func feedUDP(_ packets: [Data]) {
        for packet in packets {
            if let datagram = UDPPacket.parse(packet) {
                handleInboundUDP(datagram)
            }
        }
    }

    // MARK: - Timers

    /// Starts the lwIP timeout timer (100ms, matching `TCP_TMR_INTERVAL`).
    /// The tick suspends itself whenever lwIP's timeout list is empty so an
    /// idle tunnel stops waking the CPU 10x/sec; ``feedLwip`` re-arms it.
    func startTimeoutTimer() {
        let timer = DispatchSource.makeTimerSource(queue: lwipQueue)
        timer.schedule(
            deadline: .now() + .milliseconds(TunnelConstants.lwipTimeoutIntervalMs),
            repeating: .milliseconds(TunnelConstants.lwipTimeoutIntervalMs),
            leeway: .milliseconds(TunnelConstants.lwipTimeoutLeewayMs)
        )
        timer.setEventHandler { [weak self] in
            guard let self, self.running else { return }
            if lwip_bridge_check_timeouts() != 0 {
                self.suspendLwipTickIfNeeded()
            }
        }
        timer.resume()
        lwipTickSuspended = false
        timeoutTimer = timer
    }

    /// Suspends the drained lwIP tick; idempotent. Must run on ``lwipQueue``.
    private func suspendLwipTickIfNeeded() {
        guard let timeoutTimer, !lwipTickSuspended else { return }
        lwipTickSuspended = true
        timeoutTimer.suspend()
    }

    /// Re-arms the lwIP tick if it idled. Must run on ``lwipQueue``.
    func resumeLwipTickIfNeeded() {
        guard let timeoutTimer, lwipTickSuspended else { return }
        lwipTickSuspended = false
        timeoutTimer.resume()
    }

    /// Starts the 1s cleanup timer reaping UDP flows past their idle deadline.
    /// Runs on ``udpQueue``, which owns ``udpFlows``.
    func startUDPCleanupTimer() {
        let timer = DispatchSource.makeTimerSource(queue: udpQueue)
        timer.schedule(
            deadline: .now() + .seconds(TunnelConstants.udpCleanupIntervalSec),
            repeating: .seconds(TunnelConstants.udpCleanupIntervalSec),
            leeway: .milliseconds(TunnelConstants.udpCleanupLeewayMs)
        )
        timer.setEventHandler { [weak self] in
            guard let self, self.running else { return }
            let now = MonotonicClock.now
            var keysToRemove: [UDPFlowKey] = []
            for (key, flow) in self.udpFlows {
                if now > flow.idleDeadline {
                    flow.close()
                    keysToRemove.append(key)
                }
            }
            for key in keysToRemove {
                self.udpFlows.removeValue(forKey: key)
            }
            // Re-arm the flow-cap warning so a later storm logs its own rising edge.
            if self.udpFlowCapWarned && self.udpFlows.count < TunnelConstants.udpMaxFlows {
                self.udpFlowCapWarned = false
            }
        }
        timer.resume()
        udpCleanupTimer = timer
    }
}
