//
//  TunnelStack+IO.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import NetworkExtension

private let logger = AnywhereLogger(category: "TunnelStack")

extension TunnelStack {

    // MARK: - Output Batching
    //
    // Output ownership: two producers append IP packets to ``outputPackets``
    // under ``outputBufferLock`` — lwIP callbacks on ``lwipQueue`` (TCP), and
    // the Swift UDP/ICMP builders on ``udpQueue`` (via ``enqueueOutbound``).
    // Whoever appends with no drain in flight kicks off one ``outputQueue.async``
    // invocation of ``drainOutputLoop``. The loop pulls successive batches under
    // the lock and calls ``packetFlow.writePackets`` back-to-back on
    // ``outputQueue`` until the buffer is empty; it then clears
    // ``outputDrainInFlight`` and returns. Subsequent appends restart the
    // loop. Keeping the drain on ``outputQueue`` prevents it from
    // serializing behind lwIP work (input processing, proxy-leg
    // completions) on ``lwipQueue``. Per-packet pbuf/heap releases still fire on
    // ``lwipQueue`` (UDP/ICMP packets carry a ``noopRelease``, so they're free).

    /// Drains the output buffer on ``outputQueue`` by issuing back-to-back
    /// ``packetFlow.writePackets`` calls, each capped at
    /// ``TunnelConstants/tunnelMaxPacketsPerWrite`` (utun's empirical per-call
    /// ceiling — exceeding it trips ENOSPC). Between calls, new packets
    /// appended by lwIP show up under the lock on the next iteration.
    ///
    /// Caller contract: only invoked from the kick path in
    /// ``TunnelStack+Callbacks`` (and ``sendICMPPortUnreachable``), which
    /// flips ``outputDrainInFlight`` true under the lock first. The loop is
    /// responsible for flipping it back to false when it observes an empty
    /// buffer — that must happen under the lock, atomic with the empty
    /// check, otherwise a concurrent appender could see "drain in flight"
    /// while the loop has already decided to exit.
    func drainOutputLoop() {
        let cap = TunnelConstants.tunnelMaxPacketsPerWrite
        while true {
            var packets: [Data] = []
            var protocols: [NSNumber] = []
            var releases: [PendingRelease] = []

            outputBufferLock.withLock {
                let pending = outputPackets.count
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

            if packets.isEmpty { return }
            packetFlow?.writePackets(packets, withProtocols: protocols)

            // Free the whole batch in one ``lwipQueue.async``. ``writePackets``
            // copies into the kernel synchronously, so the underlying memory is
            // no longer referenced by the time we get here.
            if !releases.isEmpty {
                lwipQueue.async {
                    for r in releases {
                        r.fn(r.ctx)
                    }
                }
            }
        }
    }

    /// Appends a fully-formed IP packet built in Swift — a UDP response
    /// (``writeOutboundUDP``) or an ICMP unreachable (``sendICMPPortUnreachable``) —
    /// to the output buffer and kicks the drain if one isn't already running.
    /// Unlike lwIP-originated packets, these have no pbuf/heap buffer to free,
    /// so a ``noopRelease`` placeholder is appended to keep ``pendingReleases``
    /// index-aligned with ``outputPackets`` (see ``drainOutputLoop``).
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

    /// Continuously reads IP packets from the tunnel, splitting each batch
    /// across the two data planes: UDP datagrams go to ``udpQueue``
    /// (``UDPPacket`` → ``handleInboundUDP`` — lwIP is built TCP-only,
    /// `LWIP_UDP 0`), while TCP/ICMP are fed into lwIP on ``lwipQueue`` via
    /// ``lwip_bridge_input``. The two sub-batches process concurrently, so a
    /// heavy TCP burst no longer queues UDP datagrams head-of-line (and vice
    /// versa) the way the single shared queue did.
    ///
    /// Backpressure is preserved exactly: the next ``readPackets`` is issued
    /// only after *both* sub-batches finish, so at most one batch is ever in
    /// flight (utun's input buffer paces us). For the common homogeneous batch
    /// the re-arm rides the single non-empty side; only a genuinely mixed batch
    /// pays for a ``DispatchGroup``.
    func startReadingPackets() {
        packetFlow?.readPackets { [weak self] packets, _ in
            guard let self, self.running else { return }

            // Partition on the read-callback thread — only a cheap version/proto
            // header peek per packet (``UDPPacket/ipProtocol``); the heavier
            // ``parse`` runs on udpQueue. Uplink bytes are tallied per-target
            // downstream (``TCPConnection.acknowledgeReceivedBytes`` /
            // ``UDPFlow.handleReceivedData``), where the routing target is known —
            // not here, where the batch is still target-agnostic IP packets.
            //
            // Reflected packets (destination matches a configured reflection
            // address) are bounced straight back into the TUN here, before the
            // partition — they never reach lwIP, the UDP path, routing, or the
            // proxy. The snapshot is read once per batch (off ``reflector()``);
            // when the feature is off it's ``isActive == false`` and the whole
            // branch is skipped.
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
                // Nothing left to feed: an empty batch (readPackets shouldn't
                // deliver one, but re-arm defensively so the loop can't stall),
                // or a batch whose packets were all reflected.
                // (Unparseable packets aren't here: they fall to lwipBatch,
                // where lwIP drops them.)
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
                // Re-arm off the data-plane queues so the next read doesn't wait
                // behind either side's queue depth — only behind both finishing.
                group.notify(queue: DispatchQueue.global(qos: .userInitiated)) { [weak self] in
                    self?.startReadingPackets()
                }
            }
        }
    }

    /// Feeds a TCP/ICMP sub-batch into lwIP. Must run on ``lwipQueue``.
    ///
    /// The batch bracket coalesces per-segment ACKs into one per PCB and, on
    /// `_end`, walks every active TCP PCB. It's only opened here — for batches
    /// that actually contain lwIP-bound packets — so a UDP-only read (e.g. heavy
    /// QUIC) skips that walk entirely by never calling this method.
    private func feedLwip(_ packets: [Data]) {
        lwip_bridge_input_batch_begin()
        for packet in packets {
            packet.withUnsafeBytes { buffer in
                guard let baseAddress = buffer.baseAddress else { return }
                lwip_bridge_input(baseAddress, Int32(buffer.count))
            }
        }
        lwip_bridge_input_batch_end()
        // A fresh segment may have created a PCB (and thus a tcp_tmr timeout)
        // while the tick was suspended on an idle stack — re-arm so it gets
        // serviced. No-op when the tick is already running.
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

    /// Starts the lwIP periodic timeout timer (100ms interval, matching
    /// ``TunnelConstants/lwipTimeoutIntervalMs`` / `TCP_TMR_INTERVAL`).
    ///
    /// The tick services lwIP's timeout list, then **suspends itself** whenever
    /// the list is empty (no active or TIME_WAIT TCP PCB), so an idle tunnel
    /// stops waking the CPU 10x/sec. ``feedLwip`` re-arms it when an inbound
    /// segment arrives — the only thing that can create new lwIP work once every
    /// PCB has drained (all UDP and every other cyclic timer are out of the
    /// picture: UDP runs in Swift, and the rest are disabled in lwipopts.h).
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

    /// Suspends the lwIP tick after it has drained every pending timeout. Idempotent
    /// (guarded by ``lwipTickSuspended``) so the suspend count can't run away.
    /// Must run on ``lwipQueue``.
    private func suspendLwipTickIfNeeded() {
        guard let timeoutTimer, !lwipTickSuspended else { return }
        lwipTickSuspended = true
        timeoutTimer.suspend()
    }

    /// Re-arms the lwIP tick if it idled. Called from ``feedLwip`` — inbound TCP
    /// is the only thing that can schedule new lwIP timeouts once the stack is
    /// quiescent. A no-op while the tick is already running. Must run on
    /// ``lwipQueue``.
    func resumeLwipTickIfNeeded() {
        guard let timeoutTimer, lwipTickSuspended else { return }
        lwipTickSuspended = false
        timeoutTimer.resume()
    }

    /// Starts the UDP flow cleanup timer (1-second interval). Each flow is
    /// reaped once `now` passes its ``UDPFlow/idleDeadline`` — 30s after the
    /// last packet for an unreplied flow, 120s for an established one. Runs on
    /// ``udpQueue`` — it iterates and mutates ``udpFlows``, which that queue owns.
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
            // Re-arm the flow-cap warning once the table has drained back below
            // the ceiling, so a later storm logs its own rising edge instead of
            // staying silent behind the first one's latch.
            if self.udpFlowCapWarned && self.udpFlows.count < TunnelConstants.udpMaxFlows {
                self.udpFlowCapWarned = false
            }
        }
        timer.resume()
        udpCleanupTimer = timer
    }
}
