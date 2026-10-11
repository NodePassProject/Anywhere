//
//  IPStack.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

import Foundation
import Synchronization

public final class IPStack: Sendable {
    public struct Configuration: Sendable {
        public var maximumConnections: Int
        public var pendingSendBytes: Int
        public var parallelism: Int
        public var acknowledgmentDelay: Duration?

        public init(
            maximumConnections: Int = 1024,
            pendingSendBytes: Int = 64 * 1024,
            parallelism: Int = 4,
            acknowledgmentDelay: Duration? = nil
        ) {
            precondition(maximumConnections > 0 && pendingSendBytes > 0 && parallelism > 0)
            precondition(acknowledgmentDelay.map { $0 > .zero } ?? true)
            self.maximumConnections = maximumConnections
            self.pendingSendBytes = pendingSendBytes
            self.parallelism = parallelism
            self.acknowledgmentDelay = acknowledgmentDelay
        }
    }

    private final class Shard: Sendable {
        let entries = Mutex<[ConnectionKey: Stream]>([:])
    }
    
    private struct Admission {
        var closed = false
        var count = 0
        var generation: UInt64 = 0
    }
    
    private struct TimerDriver {
        var running = false
        var pending = false
        var finished = false
        var waiter: CheckedContinuation<Bool, Never>?
    }

    private struct AcknowledgmentQueue {
        var streams: [Stream] = []
        var finished = false
        var waiter: CheckedContinuation<Bool, Never>?
    }
    
    public static let tickInterval: Duration = TickClock.interval
    private static let timerTolerance: Duration = .milliseconds(50)
    private static let sleeping: UInt64 = 1 << 32
    private static let parallelPartitionLoad = 16
    
    private let admission = Mutex(Admission())
    private let shards: [Shard]
    private let configuration: Configuration
    private let outputHandler: @Sendable ([OutboundPacket]) -> Void
    private let acceptHandler: @Sendable (PendingConnection) -> Void
    private let datagramHandler: (@Sendable ([InboundDatagram]) -> Void)?
    private let synFilter: @Sendable (IPEndpoint, IPEndpoint) -> AcceptVerdict
    private let strayFilter: @Sendable (IPEndpoint, IPEndpoint) -> Bool
    private let clock = TickClock()
    private let initialSequence = Atomic<UInt32>(UInt32.random(in: .min ... .max))
    private let timerDriver = Mutex(TimerDriver())
    private let acknowledgments = Mutex(AcknowledgmentQueue())
    private let armed = Atomic<UInt64>(0)
    
    public var isIdle: Bool { admission.withLock { $0.count == 0 } }
    public var connectionCount: Int { admission.withLock { $0.count } }
    public var activeConnectionCount: Int { connections().reduce(0) { $0 + ($1.isTimeWait ? 0 : 1) } }
    
    private var ticks: UInt32 { clock.now }

    public init(
        configuration: Configuration = Configuration(),
        output: @escaping @Sendable ([OutboundPacket]) -> Void,
        accept: @escaping @Sendable (PendingConnection) -> Void,
        datagrams: (@Sendable ([InboundDatagram]) -> Void)? = nil,
        synFilter: @escaping @Sendable (IPEndpoint, IPEndpoint) -> AcceptVerdict = { _, _ in .accept },
        strayFilter: @escaping @Sendable (IPEndpoint, IPEndpoint) -> Bool = { _, _ in true }
    ) {
        precondition(configuration.maximumConnections > 0 && configuration.pendingSendBytes > 0 && configuration.parallelism > 0)
        self.configuration = configuration
        outputHandler = output
        acceptHandler = accept
        datagramHandler = datagrams
        self.synFilter = synFilter
        self.strayFilter = strayFilter
        shards = (0..<max(16, configuration.parallelism * 4)).map { _ in Shard() }
    }
    
    public func input(_ packet: Data) {
        packet.withUnsafeBytes { input([$0]) }
    }

    public func input(_ packets: [Data]) {
        var buffers: [UnsafeRawBufferPointer] = []
        buffers.reserveCapacity(packets.count)
        withBuffers(of: packets[...], appendingTo: &buffers)
    }

    private func withBuffers(of packets: ArraySlice<Data>, appendingTo buffers: inout [UnsafeRawBufferPointer]) {
        guard let first = packets.first else {
            input(buffers)
            return
        }
        first.withUnsafeBytes { bytes in
            buffers.append(bytes)
            withBuffers(of: packets.dropFirst(), appendingTo: &buffers)
        }
    }

    public func input(_ packets: [UnsafeRawBufferPointer]) {
        guard let generation = liveGeneration(), !packets.isEmpty else { return }
        var batch = InboundBatch(decodesUDP: datagramHandler != nil)
        for packet in packets { batch.decode(packet) }
        guard isLive(generation) else { return }
        if !batch.control.isEmpty { outputHandler(batch.control) }
        if !batch.datagrams.isEmpty { datagramHandler?(batch.datagrams) }
        deliver(batch.groups, segmentCount: batch.segmentCount, generation: generation)
    }

    private func deliver(_ groups: [[InboundTCP]], segmentCount: Int, generation: UInt64) {
        let partitionCount = configuration.parallelism
        guard partitionCount > 1, segmentCount >= 2 * Self.parallelPartitionLoad else {
            for group in groups { deliverGroup(group, generation: generation) }
            return
        }
        var partitions = Array(repeating: [Int](), count: partitionCount)
        var loads = Array(repeating: 0, count: partitionCount)
        for (position, group) in groups.enumerated() {
            let partition = Int(group[0].key.fingerprint % UInt64(partitionCount))
            partitions[partition].append(position)
            loads[partition] += group.count
        }
        let heavy = loads.indices.filter { loads[$0] >= Self.parallelPartitionLoad }.map { partitions[$0] }
        guard heavy.count > 1 else {
            for group in groups { deliverGroup(group, generation: generation) }
            return
        }
        DispatchQueue.concurrentPerform(iterations: heavy.count) { index in
            for position in heavy[index] { deliverGroup(groups[position], generation: generation) }
        }
        for partition in partitions.indices where loads[partition] < Self.parallelPartitionLoad {
            for position in partitions[partition] { deliverGroup(groups[position], generation: generation) }
        }
    }

    private func liveGeneration() -> UInt64? {
        admission.withLock { $0.closed ? nil : $0.generation }
    }
    
    private func isLive(_ generation: UInt64) -> Bool {
        admission.withLock { !$0.closed && $0.generation == generation }
    }
    
    private func shard(for key: ConnectionKey) -> Shard {
        shards[Int(key.fingerprint % UInt64(shards.count))]
    }

    private func deliver(_ packet: InboundTCP, generation: UInt64) {
        let shard = shard(for: packet.key)
        if let connection = shard.entries.withLock({ $0[packet.key] }) {
            if connection.generation == generation { connection.input(packet) }
            return
        }
        let header = packet.header
        if header.flags.contains(.rst) { return }
        if header.flags.contains(.ack) {
            guard strayFilter(packet.key.remote, packet.key.local), isLive(generation) else { return }
            reset(packet, sequenceNumber: header.acknowledgmentNumber)
            return
        }
        guard header.flags.contains(.syn) else { return }
        switch synFilter(packet.key.remote, packet.key.local) {
        case .accept:
            break
        case .drop:
            return
        case .reset:
            guard isLive(generation) else { return }
            reset(packet, sequenceNumber: 0)
            return
        }
        if connectionCount >= configuration.maximumConnections {
            let candidates = connections()
            if let timeWait = candidates.first(where: { $0.isTimeWait }) {
                _ = timeWait.reclaimIfClosing()
            } else {
                _ = candidates.first(where: { $0.reclaimIfClosing() })
            }
        }
        let connection: Stream? = shard.entries.withLock { entries in
            if let existing = entries[packet.key] { return existing }
            let reserved = admission.withLock { admission in
                guard !admission.closed, admission.generation == generation,
                      admission.count < configuration.maximumConnections else { return false }
                admission.count += 1
                return true
            }
            guard reserved else { return nil }
            let connection = Stream(
                packet: packet,
                initialSequenceNumber: initialSequence.wrappingAdd(64001, ordering: .relaxed).oldValue,
                clock: clock,
                generation: generation,
                pendingLimit: configuration.pendingSendBytes,
                delaysAcknowledgment: configuration.acknowledgmentDelay != nil,
                output: { [weak self] packets in self?.outputHandler(packets) },
                ready: { [weak self] pending in
                    guard let self else { pending.reject(); return }
                    self.acceptHandler(pending)
                },
                removed: { [weak self] in self?.remove($0) },
                schedule: { [weak self] in self?.schedule($0) },
                delayAcknowledgment: { [weak self] in self?.delayAcknowledgment($0) }
            )
            entries[packet.key] = connection
            return connection
        }
        connection?.input(packet)
    }

    private func reset(_ packet: InboundTCP, sequenceNumber: UInt32) {
        let header = packet.header
        let length = UInt32(packet.payload.count) + (header.flags.contains(.syn) || header.flags.contains(.fin) ? 1 : 0)
        guard let reset = OutboundPacket(
            resetFrom: packet.key.local,
            to: packet.key.remote,
            sequenceNumber: sequenceNumber,
            acknowledgmentNumber: header.sequenceNumber &+ length
        ) else { return }
        outputHandler([reset])
    }

    private func deliverGroup(_ packets: [InboundTCP], generation: UInt64) {
        guard let first = packets.first else { return }
        var position = 0
        while position < packets.count {
            guard isLive(generation) else { return }
            if let connection = shard(for: first.key).entries.withLock({ $0[first.key] }),
               connection.generation == generation {
                let end = min(position + 32, packets.count)
                let processed = connection.inputBatch(packets[position..<end])
                if processed == 0 { remove(connection) }
                position += processed
            } else {
                deliver(packets[position], generation: generation)
                position += 1
            }
        }
    }

    private func remove(_ connection: Stream) {
        let removed = shard(for: connection.key).entries.withLock { entries in
            guard entries[connection.key] === connection else { return false }
            entries.removeValue(forKey: connection.key)
            return true
        }
        if removed { admission.withLock { $0.count -= 1 } }
    }

    public func connections() -> [Stream] {
        shards.flatMap { $0.entries.withLock { Array($0.values) } }
    }
    
    @discardableResult public func tick() -> Int {
        expire(at: ticks).active
    }

    private func expire(at now: UInt32) -> (active: Int, deadline: UInt32?) {
        var active = 0
        var next: UInt32?
        for connection in connections() {
            var deadline = connection.scheduledDeadline
            if deadline != 0, !Sequence.lessThan(now, deadline) { deadline = connection.expire() }
            if !connection.isLingering { active += 1 }
            if deadline != 0, next.map({ Sequence.lessThan(deadline, $0) }) ?? true { next = deadline }
        }
        return (active, next)
    }

    private func schedule(_ deadline: UInt32) {
        let armed = self.armed.load(ordering: .sequentiallyConsistent)
        guard armed < Self.sleeping || Sequence.lessThan(deadline, UInt32(truncatingIfNeeded: armed)) else { return }
        let waiter = timerDriver.withLock { driver -> CheckedContinuation<Bool, Never>? in
            guard let waiter = driver.waiter else { driver.pending = true; return nil }
            driver.waiter = nil
            return waiter
        }
        waiter?.resume(returning: true)
    }

    private func waitForSchedule() async -> Bool {
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let immediate = timerDriver.withLock { driver -> Bool? in
                    if driver.finished || Task.isCancelled { return false }
                    if driver.pending { driver.pending = false; return true }
                    driver.waiter = continuation
                    return nil
                }
                if let immediate { continuation.resume(returning: immediate) }
            }
        } onCancel: {
            timerDriver.withLock { driver in
                defer { driver.waiter = nil }
                return driver.waiter
            }?.resume(returning: false)
        }
    }

    private func sleep(until deadline: UInt32) async -> Bool {
        let instant = clock.instant(of: deadline)
        return await withTaskGroup(of: Bool.self) { group in
            group.addTask { (try? await Task.sleep(until: instant, tolerance: Self.timerTolerance, clock: .continuous)) != nil }
            group.addTask { await self.waitForSchedule() }
            defer { group.cancelAll() }
            return await group.next() ?? false
        }
    }

    private func finishTimer() {
        timerDriver.withLock { driver in
            driver.finished = true
            defer { driver.waiter = nil }
            return driver.waiter
        }?.resume(returning: false)
        acknowledgments.withLock { queue in
            queue.finished = true
            queue.streams.removeAll()
            defer { queue.waiter = nil }
            return queue.waiter
        }?.resume(returning: false)
    }

    private func delayAcknowledgment(_ stream: Stream) {
        acknowledgments.withLock { queue -> CheckedContinuation<Bool, Never>? in
            guard !queue.finished else { return nil }
            queue.streams.append(stream)
            defer { queue.waiter = nil }
            return queue.waiter
        }?.resume(returning: true)
    }

    private func waitForDelayedAcknowledgments() async -> Bool {
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let immediate = acknowledgments.withLock { queue -> Bool? in
                    if queue.finished || Task.isCancelled { return false }
                    if !queue.streams.isEmpty { return true }
                    queue.waiter = continuation
                    return nil
                }
                if let immediate { continuation.resume(returning: immediate) }
            }
        } onCancel: {
            acknowledgments.withLock { queue in
                defer { queue.waiter = nil }
                return queue.waiter
            }?.resume(returning: false)
        }
    }

    private func flushDelayedAcknowledgments(after delay: Duration) async {
        var streams: [Stream] = []
        while await waitForDelayedAcknowledgments() {
            guard (try? await Task.sleep(for: delay, tolerance: delay / 2)) != nil else { return }
            acknowledgments.withLock { swap(&streams, &$0.streams) }
            for stream in streams { stream.flushAcknowledgment() }
            streams.removeAll(keepingCapacity: true)
        }
    }
    
    @concurrent public func runTimer(_ onTick: @escaping @Sendable (Int) -> Void = { _ in }) async {
        let claimed = timerDriver.withLock { driver -> Bool in
            guard !driver.running else { return false }
            driver.running = true
            return true
        }
        guard claimed else { return }
        defer {
            armed.store(0, ordering: .sequentiallyConsistent)
            timerDriver.withLock { $0.running = false }
        }
        guard let delay = configuration.acknowledgmentDelay else {
            await runTicks(onTick)
            return
        }
        await withDiscardingTaskGroup { group in
            group.addTask { await self.flushDelayedAcknowledgments(after: delay) }
            await runTicks(onTick)
            group.cancelAll()
        }
    }

    private func runTicks(_ onTick: @Sendable (Int) -> Void) async {
        while !Task.isCancelled {
            guard liveGeneration() != nil else { return }
            armed.store(0, ordering: .sequentiallyConsistent)
            let (active, deadline) = expire(at: ticks)
            onTick(active)
            if let deadline {
                armed.store(Self.sleeping | UInt64(deadline), ordering: .sequentiallyConsistent)
                guard await sleep(until: deadline) else { return }
            } else {
                guard await waitForSchedule() else { return }
            }
        }
    }
    
    public func abortAllConnections() {
        let generation = admission.withLock { $0.generation &+= 1; return $0.generation }
        for connection in connections() {
            let age = generation &- connection.generation
            if age > 0 && age < 0x8000_0000_0000_0000 { connection.cancel() }
        }
    }

    public func shutdown() {
        admission.withLock { $0.closed = true; $0.generation &+= 1 }
        finishTimer()
        for connection in connections() { connection.cancel() }
    }

    deinit {
        finishTimer()
        for shard in shards {
            let live = shard.entries.withLock { entries in
                let live = Array(entries.values)
                entries.removeAll()
                return live
            }
            for connection in live { connection.cancel() }
        }
    }
}
