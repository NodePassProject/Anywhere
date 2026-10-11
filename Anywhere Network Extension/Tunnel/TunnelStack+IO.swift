//
//  TunnelStack+IO.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import Synchronization
@preconcurrency import NetworkExtension
import AnywhereIP

nonisolated private let logger = AnywhereLogger(category: "TunnelStack+IO")

extension TunnelStack {

    // MARK: - Output Batching

    nonisolated func claimOutputDrain() -> Bool {
        outputBuffer.withLock { $0.claimDrain() }
    }

    nonisolated func drainOutput() {
        var packets: [OutboundPacket] = []
        while let writer = outputBuffer.withLock({ $0.take(&packets) }) {
            writer.write(packets)
            packets.removeAll(keepingCapacity: true)
        }
    }

    nonisolated func flushOutputBuffer() {
        if claimOutputDrain() { drainOutput() }
    }

    nonisolated func enqueueOutbound(_ packet: OutboundPacket) {
        let drains = outputBuffer.withLock { buffer in
            guard buffer.writer != nil else { return false }
            buffer.packets.append(packet)
            return buffer.claimDrain()
        }
        if drains { drainOutput() }
    }

    nonisolated func enqueueTCPOutput(_ packets: [OutboundPacket], generation: UInt64) {
        let drains = outputBuffer.withLock { buffer in
            guard buffer.generation == generation, buffer.writer != nil, !packets.isEmpty else { return false }
            buffer.packets.append(contentsOf: packets)
            return buffer.claimDrain()
        }
        if drains { drainOutput() }
    }

    // MARK: - Packet Reading

    nonisolated func runReadLoop(packetFlow: NEPacketTunnelFlow, udpPlane: UDPPlane) async {
        let intake = AsyncInbox<[InboundDatagram]>(capacity: TunnelConstants.udpIntakeBacklog)
        datagramIntake.withLock { $0 = intake }
        let reader = PacketReader(flow: packetFlow) { [weak self] packets in
            self?.processInbound(packets)
        }
        await withDiscardingTaskGroup { group in
            group.addTask {
                while let batches = try? await intake.nextBatch() {
                    await udpPlane.feed(batches.count == 1 ? batches[0] : Array(batches.joined()))
                }
            }
            await reader.run()
            datagramIntake.withLock { if $0 === intake { $0 = nil } }
            intake.finish()
        }
    }

    private nonisolated func processInbound(_ packets: [UnsafeRawBufferPointer]) {
        let drains = claimOutputDrain()
        var batch = packets
        if reflectionEnabled {
            batch = []
            batch.reserveCapacity(packets.count)
            for packet in packets {
                if let reflected = Reflector.reflect(packet) {
                    enqueueOutbound(reflected)
                    continue
                }
                batch.append(packet)
            }
        }
        if !batch.isEmpty, let ipStack = liveIPStack.withLock({ $0 }) {
            ipStack.input(batch)
        }
        if drains { drainOutput() }
    }
    
    nonisolated func admitDatagrams(_ batch: [InboundDatagram]) {
        datagramIntake.withLock { $0 }?.yield(batch)
    }

    // MARK: - Timers

    func startIPStackTick() {
        guard let ipStack else { return }
        ipStackTick = Task { await ipStack.runTimer() }
    }

    nonisolated func scheduleTCPIdleSweep(at deadline: TimeInterval) {
        let armed = tcpIdleSweepArmed.load(ordering: .sequentiallyConsistent)
        if deadline < armed { tcpIdleSweepRegistration.withLock { $0 }?.poke() }
    }

    nonisolated func runTCPIdleSweep() async {
        let source = TCPIdleSweepSource(stack: self)
        let registration = TickScheduler.shared.register(source)
        tcpIdleSweepRegistration.withLock { $0 = registration }
        await Task.suspendUntilCancelled()
        tcpIdleSweepRegistration.withLock { if $0 === registration { $0 = nil } }
        registration.cancel()
        tcpIdleSweepArmed.store(.infinity, ordering: .sequentiallyConsistent)
    }

    nonisolated func scheduleUDPCleanup(at deadline: TimeInterval) {
        udpCleanupSource.withLock { $0 }?.lower(to: deadline)
    }

    nonisolated func runUDPCleanupLoop(udpPlane: UDPPlane) async {
        let source = UDPCleanupSource(stack: self, plane: udpPlane)
        let registration = TickScheduler.shared.register(source)
        source.attach(registration)
        udpCleanupSource.withLock { $0 = source }
        await Task.suspendUntilCancelled()
        udpCleanupSource.withLock { if $0 === source { $0 = nil } }
        registration.cancel()
    }
}

nonisolated final class TCPIdleSweepSource: DeadlineSource, @unchecked Sendable {
    private weak var stack: TunnelStack?

    init(stack: TunnelStack) {
        self.stack = stack
    }

    func nextDeadline() -> Deadline? {
        guard let stack else { return nil }
        var next = TimeInterval.infinity
        for connection in stack.tcpConnections.withLock({ Array($0.connections.values) }) {
            guard let deadline = connection.idleDeadline else { continue }
            next = min(next, deadline)
        }
        stack.tcpIdleSweepArmed.store(next, ordering: .sequentiallyConsistent)
        guard next.isFinite else { return nil }
        return Deadline(atSeconds: next, precision: .relaxed)
    }

    func fire(now: MonotonicClock.Instant) {
        guard let stack else { return }
        let seconds = now.seconds
        for connection in stack.tcpConnections.withLock({ Array($0.connections.values) }) {
            guard let deadline = connection.idleDeadline, deadline <= seconds else { continue }
            connection.expireIdle()
        }
    }
}

nonisolated final class UDPCleanupSource: DeadlineSource, @unchecked Sendable {
    private weak var stack: TunnelStack?
    private let plane: UDPPlane
    private let deadline = Mutex<TimeInterval?>(nil)
    private let registration = Mutex<DeadlineRegistration?>(nil)

    init(stack: TunnelStack, plane: UDPPlane) {
        self.stack = stack
        self.plane = plane
    }

    func attach(_ registration: DeadlineRegistration) {
        self.registration.withLock { $0 = registration }
    }

    func lower(to candidate: TimeInterval) {
        let changed: Bool = deadline.withLock { current in
            if let current, current <= candidate { return false }
            current = candidate
            return true
        }
        if changed { registration.withLock { $0 }?.poke() }
    }

    func nextDeadline() -> Deadline? {
        deadline.withLock { $0 }.map { Deadline(atSeconds: $0, precision: .relaxed) }
    }

    func fire(now: MonotonicClock.Instant) {
        deadline.withLock { $0 = nil }
        guard let stack else { return }
        let plane = plane
        Task { [weak self, weak stack] in
            guard let stack, stack.publishedPhase.load(ordering: .relaxed) == .running else { return }
            guard let next = await plane.cleanup() else { return }
            self?.lower(to: next + TimeInterval(TunnelConstants.udpCleanupCoalescingSec))
        }
    }
}
