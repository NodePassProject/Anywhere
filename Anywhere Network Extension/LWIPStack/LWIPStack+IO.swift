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
    ///
    /// Re-flushing after a write completes is signalled via ``outputDrainSource``
    /// instead of a per-write `lwipQueue.async` from the output queue. The
    /// source coalesces tightly-spaced signals (every TCP-recv ACK on a busy
    /// upload path triggers a writePackets, easily 300+/s across multiple
    /// connections) into a single `lwipQueue` handler invocation when the
    /// queue is busy with input/completion work.
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
        let drainSource = outputDrainSource
        outputQueue.async { [weak self] in
            self?.packetFlow?.writePackets(packets, withProtocols: protocols)
            // Cheaper than `lwipQueue.async`: multiple post-write signals
            // arriving while lwipQueue is busy collapse into one handler
            // invocation that drains them all together.
            drainSource?.add(data: 1)
        }
    }

    /// Creates the coalescing drain source bound to ``lwipQueue``. Each call
    /// to ``DispatchSource/add(data:)`` from outputQueue (after `writePackets`
    /// completes) signals the source; the handler fires once on lwipQueue
    /// per "free moment", clears ``outputWriteInFlight``, and re-flushes if
    /// more output has accumulated. Idempotent within a single handler call:
    /// `data` (the accumulated count) isn't read because the work to do is
    /// the same regardless of how many writes signalled.
    func startOutputDrainSource() {
        let source = DispatchSource.makeUserDataAddSource(queue: lwipQueue)
        source.setEventHandler { [weak self] in
            guard let self else { return }
            self.outputWriteInFlight = false
            if !self.outputPackets.isEmpty {
                self.flushOutputPackets()
            }
        }
        source.activate()
        outputDrainSource = source
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
