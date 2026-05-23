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
    // Output ownership: lwIP callbacks (on ``lwipQueue``) append IP packets
    // to ``outputPackets`` under ``outputBufferLock`` and, when no drain is
    // in flight, kick off one ``outputQueue.async`` invocation of
    // ``drainOutputLoop``. The loop pulls successive batches under the
    // lock and calls ``packetFlow.writePackets`` back-to-back on
    // ``outputQueue`` until the buffer is empty; it then clears
    // ``outputDrainInFlight`` and returns. Subsequent appends restart the
    // loop. Keeping the drain on ``outputQueue`` prevents it from
    // serializing behind lwIP work (input processing, proxy-leg
    // completions) on ``lwipQueue``.

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

    /// Continuously reads IP packets from the tunnel. UDP is handled in Swift
    /// (``UDPPacket`` → ``handleInboundUDP``) so the vendored lwIP can build
    /// TCP-only; TCP/ICMP are fed into lwIP via ``lwip_bridge_input``.
    func startReadingPackets() {
        packetFlow?.readPackets { [weak self] packets, _ in
            guard let self, self.running else { return }

            var uploadBytes: Int64 = 0
            for packet in packets {
                uploadBytes += Int64(packet.count)
            }

            self.lwipQueue.async {
                self.totalBytesOut += uploadBytes
                // The batch brackets only the packets actually fed to lwIP:
                // begin/end coalesces per-segment ACKs into one per PCB and, on
                // _end, walks every active TCP PCB. Opening it lazily skips that
                // walk for UDP-only batches (e.g. heavy QUIC). See
                // `lwip_bridge_input_batch_begin`.
                var batchOpen = false
                for packet in packets {
                    if let info = UDPPacket.ipProtocol(of: packet), info.proto == UDPPacket.ipProtocolUDP {
                        if let datagram = UDPPacket.parse(packet) {
                            self.handleInboundUDP(datagram)
                        }
                        continue
                    }
                    if !batchOpen {
                        lwip_bridge_input_batch_begin()
                        batchOpen = true
                    }
                    packet.withUnsafeBytes { buffer in
                        guard let baseAddress = buffer.baseAddress else { return }
                        lwip_bridge_input(baseAddress, Int32(buffer.count))
                    }
                }
                if batchOpen { lwip_bridge_input_batch_end() }
                self.startReadingPackets()
            }
        }
    }

    // MARK: - Timers

    /// Starts the lwIP periodic timeout timer (250ms interval).
    func startTimeoutTimer() {
        let timer = DispatchSource.makeTimerSource(queue: lwipQueue)
        timer.schedule(
            deadline: .now() + .milliseconds(TunnelConstants.lwipTimeoutIntervalMs),
            repeating: .milliseconds(TunnelConstants.lwipTimeoutIntervalMs)
        )
        timer.setEventHandler { [weak self] in
            guard let self, self.running else { return }
            lwip_bridge_check_timeouts()
        }
        timer.resume()
        timeoutTimer = timer
    }

    /// Starts the UDP flow cleanup timer (1-second interval, 300-second idle timeout).
    func startUDPCleanupTimer() {
        let timer = DispatchSource.makeTimerSource(queue: lwipQueue)
        timer.schedule(
            deadline: .now() + .seconds(TunnelConstants.udpCleanupIntervalSec),
            repeating: .seconds(TunnelConstants.udpCleanupIntervalSec)
        )
        timer.setEventHandler { [weak self] in
            guard let self, self.running else { return }
            let now = CFAbsoluteTimeGetCurrent()
            var keysToRemove: [UDPFlowKey] = []
            for (key, flow) in self.udpFlows {
                if now - flow.lastActivity > TunnelConstants.udpIdleTimeout {
                    flow.close()
                    keysToRemove.append(key)
                }
            }
            for key in keysToRemove {
                self.udpFlows.removeValue(forKey: key)
            }
        }
        timer.resume()
        udpCleanupTimer = timer
    }
}
