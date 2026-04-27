//
//  LWIPStack+IO.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/30/26.
//

import Foundation
import NetworkExtension

private let logger = AnywhereLogger(category: "LWIPStack")

extension LWIPStack {

    // MARK: - Output Batching

    /// Flushes accumulated output packets to the TUN device immediately.
    ///
    /// Called inline from download write paths (``LWIPTCPConnection.writeToLWIP``
    /// and ``drainPendingWrite``) to eliminate the extra dispatch-cycle latency
    /// of the deferred ``lwipQueue.async`` flush. The deferred path still serves
    /// as the fallback for output generated during input batch processing
    /// (``startReadingPackets`` → ``lwip_bridge_input`` loop), where batching
    /// across many connections is desirable.
    ///
    /// Safe to call at any time on lwipQueue — ``flushOutputPackets`` is a no-op
    /// when there are no accumulated packets or a write is already in flight.
    func flushOutputInline() {
        flushOutputPackets()
    }

    /// Flushes accumulated output packets to the TUN device, capping each
    /// writePackets call to ``TunnelConstants/tunnelMaxPacketsPerWrite``.
    /// Called via deferred lwipQueue.async after the current batch of
    /// lwip_bridge_input calls completes.
    ///
    /// Only one writePackets call is in flight at a time. While a write is
    /// executing, new packets accumulate and the next batch is flushed when
    /// the previous write completes. The per-flush cap plus the queue-hop
    /// between successive batches gives utun room to drain and prevents
    /// ENOSPC drops under heavy downlink load.
    func flushOutputPackets() {
        outputFlushScheduled = false
        guard !outputPackets.isEmpty, !outputWriteInFlight else { return }
        let maxPacketCount = TunnelConstants.tunnelMaxPacketsPerWrite
        let packets: [Data]
        let protocols: [NSNumber]
        if outputPackets.count <= maxPacketCount {
            packets = outputPackets
            protocols = outputProtocols
            outputPackets = []
            outputProtocols = []
            outputPackets.reserveCapacity(maxPacketCount)
            outputProtocols.reserveCapacity(maxPacketCount)
        } else {
            packets = Array(outputPackets.prefix(maxPacketCount))
            protocols = Array(outputProtocols.prefix(maxPacketCount))
            outputPackets.removeFirst(maxPacketCount)
            outputProtocols.removeFirst(maxPacketCount)
        }
        outputWriteInFlight = true
        outputQueue.async { [weak self] in
            self?.packetFlow?.writePackets(packets, withProtocols: protocols)
            self?.lwipQueue.async {
                guard let self else { return }
                self.outputWriteInFlight = false
                if !self.outputPackets.isEmpty {
                    self.flushOutputPackets()
                }
            }
        }
    }

    // MARK: - Packet Reading

    /// Continuously reads IP packets from the tunnel and feeds them into lwIP.
    func startReadingPackets() {
        packetFlow?.readPackets { [weak self] packets, _ in
            guard let self, self.running else { return }

            var uploadBytes: Int64 = 0
            for packet in packets {
                uploadBytes += Int64(packet.count)
            }

            self.lwipQueue.async {
                self.totalBytesOut += uploadBytes
                for packet in packets {
                    packet.withUnsafeBytes { buffer in
                        guard let baseAddress = buffer.baseAddress else { return }
                        lwip_bridge_input(baseAddress, Int32(buffer.count))
                    }
                }
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

    /// Starts the UDP flow cleanup timer (1-second interval, 60-second idle timeout).
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
