//
//  Stream.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

import Foundation
import Synchronization

public final class Stream: Sendable {
    private enum Admission { case handshake, pending, accepted, rejected }

    private enum Publication: Sendable {
        case output(OutboundPacket)
        case ready
        case remove
        case delayAcknowledgment
        case wake(CheckedContinuation<Void, Never>)
    }

    private enum Role { case reader, writer, acknowledger }

    private struct Waiter {
        private enum Wakeup {
            case idle
            case signaled
            case parked(CheckedContinuation<Void, Never>)
        }

        private(set) var isBusy = false
        private var wakeup = Wakeup.idle

        mutating func hold(_ busy: Bool) {
            isBusy = busy
            if busy { wakeup = .idle }
        }

        mutating func signal() -> CheckedContinuation<Void, Never>? {
            defer { wakeup = .signaled }
            guard case .parked(let continuation) = wakeup else { return nil }
            return continuation
        }

        mutating func park(_ continuation: CheckedContinuation<Void, Never>) -> Bool {
            guard case .signaled = wakeup else {
                wakeup = .parked(continuation)
                return true
            }
            wakeup = .idle
            return false
        }
    }

    private enum Outcome<Value: Sendable>: Sendable {
        case finished(Value)
        case failure(ConnectionError)
        case wait

        var isWaiting: Bool {
            switch self {
            case .wait: true
            case .finished, .failure: false
            }
        }
    }

    private struct State {
        let core: ControlBlock
        let pendingLimit: Int
        let writeThreshold: Int
        var started = false
        var admission = Admission.handshake
        var admissionTick: UInt32 = 0
        var input = ReceiveBuffer()
        var deferredAcknowledgment: OutboundPacket?
        var deliveredBytes = 0
        var receivedFIN = false
        var failure: ConnectionError?
        var ended = false
        var closing = false
        var sendingFinished = false
        var pending: [Data] = []
        var pendingOffset = 0
        var pendingBytes = 0
        var reader = Waiter()
        var writer = Waiter()
        var acknowledger = Waiter()
        var reclaimableSince: UInt32?
        var acknowledgmentQueued = false
        var publications: [Publication] = []
        var draining = false

        init(packet: InboundTCP, initialSequenceNumber: UInt32, ticks: UInt32, pendingLimit: Int, delaysAcknowledgment: Bool) {
            let context = Context(key: packet.key, initialSequenceNumber: initialSequenceNumber, ticks: ticks)
            core = ControlBlock(
                stack: context,
                key: packet.key,
                initialSequenceNumber: packet.header.sequenceNumber,
                peerWindow: packet.header.window,
                options: packet.options,
                delaysAcknowledgment: delaysAcknowledgment
            )
            self.pendingLimit = pendingLimit
            writeThreshold = max(1, pendingLimit / 2)
        }

        var deadline: UInt32? {
            var deadline = core.nextDeadline
            if case .pending = admission, core.state != .timeWait, core.state != .closed {
                let expiry = TickClock.align(admissionTick, after: Constants.synReceivedTimeout + 1)
                if deadline.map({ Sequence.lessThan(expiry, $0) }) ?? true { deadline = expiry }
            }
            if let reclaimableSince {
                let reclaim = TickClock.align(reclaimableSince, after: Constants.arenaReclaimDelay)
                if deadline.map({ Sequence.lessThan(reclaim, $0) }) ?? true { deadline = reclaim }
            }
            if let unsealedSince = input.unsealedSince {
                let seal = TickClock.align(unsealedSince, after: Constants.receiveSealDelay)
                if deadline.map({ Sequence.lessThan(seal, $0) }) ?? true { deadline = seal }
            }
            guard let deadline else { return nil }
            let now = core.stack.ticks
            return Sequence.lessThan(now, deadline) ? deadline : now &+ 1
        }

        mutating func withWaiter<T>(_ role: Role, _ body: (inout Waiter) -> T) -> T {
            switch role {
            case .reader: body(&reader)
            case .writer: body(&writer)
            case .acknowledger: body(&acknowledger)
            }
        }

        mutating func wakeReaders() {
            if let continuation = reader.signal() { publications.append(.wake(continuation)) }
        }

        mutating func wakeWriters() {
            if ended || closing || sendingFinished || pendingLimit - pendingBytes >= writeThreshold,
               let continuation = writer.signal() {
                publications.append(.wake(continuation))
            }
            if ended || (pendingBytes == 0 && core.sendQueueLength == 0),
               let continuation = acknowledger.signal() {
                publications.append(.wake(continuation))
            }
        }

        mutating func observeArena() {
            let arena = core.arena
            guard arena.isReclaimable else {
                reclaimableSince = nil
                return
            }
            if core.state >= .timeWait {
                arena.reclaim()
                reclaimableSince = nil
            } else if reclaimableSince == nil {
                reclaimableSince = core.stack.ticks
            }
        }

        mutating func harvest() {
            guard !core.stack.effects.isEmpty else { return }
            var effects = core.stack.effects
            core.stack.effects = []
            defer {
                effects.removeAll(keepingCapacity: true)
                if core.stack.effects.isEmpty { core.stack.effects = effects }
            }
            for effect in effects {
                switch effect {
                case .packet(let packet):
                    if case .pending = admission, !packet.flags.contains(.rst) {
                        deferredAcknowledgment = packet
                    } else {
                        publications.append(.output(packet))
                    }
                case .received(let bytes, let push):
                    if !ended {
                        input.append(bytes, push: push, ticks: core.stack.ticks)
                        if input.hasReadableChunk(flushing: false) { wakeReaders() }
                    }
                case .acknowledged: wakeWriters()
                case .ready:
                    if case .handshake = admission {
                        admission = .pending
                        admissionTick = core.stack.ticks
                        publications.append(.ready)
                    }
                case .fin: receivedFIN = true; wakeReaders()
                case .failed(let error): finish(error)
                case .ended: finish(nil)
                case .removed: publications.append(.remove)
                case .timeWait: break
                }
            }
        }

        mutating func finish(_ error: ConnectionError?) {
            if !ended { failure = error }
            ended = true
            if error != nil {
                admission = .rejected
                input.removeAll()
            }
            deferredAcknowledgment = nil
            pending.removeAll(); pendingOffset = 0; pendingBytes = 0
            wakeReaders(); wakeWriters()
        }

        mutating func pump() {
            guard !ended else { return }
            while let first = pending.first {
                let written = first.withUnsafeBytes { bytes in
                    core.write(UnsafeRawBufferPointer(rebasing: bytes[pendingOffset...]))
                }
                guard written > 0 else { break }
                pendingOffset += written
                pendingBytes -= written
                if pendingOffset == first.count {
                    pending.removeFirst()
                    pendingOffset = 0
                }
            }
            if sendingFinished && pendingBytes == 0 { core.shutdownSend() }
            if closing && pendingBytes == 0 {
                core.close()
                finish(nil)
            }
            core.output()
            harvest()
            wakeWriters()
        }

        mutating func read() -> Outcome<Data?> {
            if closing { return .finished(nil) }
            if case .accepted = admission, let data = input.next(flushing: receivedFIN || ended) {
                deliveredBytes += data.count
                return .finished(data)
            }
            if let failure { return .failure(failure) }
            if ended || receivedFIN { return .finished(nil) }
            return .wait
        }

        mutating func write(_ data: Data, from offset: inout Int) -> Outcome<Void> {
            guard !ended, !closing, !sendingFinished else { return .failure(failure ?? .closed) }
            while offset < data.count {
                let count = min(data.count - offset, pendingLimit - pendingBytes)
                guard count > 0 else { return .wait }
                let start = data.startIndex + offset
                pending.append(data[start..<(start + count)])
                pendingBytes += count
                offset += count
                pump()
                guard !ended else { break }
            }
            return offset == data.count ? .finished(()) : .failure(failure ?? .closed)
        }

        func acknowledgment() -> Outcome<Void> {
            if let failure { return .failure(failure) }
            if pendingBytes == 0 && core.sendQueueLength == 0 { return .finished(()) }
            return ended ? .failure(.closed) : .wait
        }
    }

    public let source: IPEndpoint
    public let destination: IPEndpoint
    let key: ConnectionKey
    let generation: UInt64
    private let state: Mutex<State>
    private let clock: TickClock
    private let scheduled = Atomic<UInt32>(0)
    private let lingering = Atomic<Bool>(false)
    private let output: @Sendable ([OutboundPacket]) -> Void
    private let ready: @Sendable (PendingConnection) -> Void
    private let removed: @Sendable (Stream) -> Void
    private let schedule: @Sendable (UInt32) -> Void
    private let delayAcknowledgment: @Sendable (Stream) -> Void

    public var isAttached: Bool { state.withLock { !$0.ended && !$0.closing } }
    public var sendBufferSpace: Int { state.withLock { $0.core.sendBufferSpace } }
    var isTimeWait: Bool { state.withLock { $0.core.state == .timeWait } }
    var isLingering: Bool { lingering.load(ordering: .relaxed) }
    var scheduledDeadline: UInt32 { scheduled.load(ordering: .sequentiallyConsistent) }

    init(
        packet: InboundTCP,
        initialSequenceNumber: UInt32,
        clock: TickClock,
        generation: UInt64,
        pendingLimit: Int,
        delaysAcknowledgment: Bool,
        output: @escaping @Sendable ([OutboundPacket]) -> Void,
        ready: @escaping @Sendable (PendingConnection) -> Void,
        removed: @escaping @Sendable (Stream) -> Void,
        schedule: @escaping @Sendable (UInt32) -> Void,
        delayAcknowledgment: @escaping @Sendable (Stream) -> Void
    ) {
        key = packet.key
        self.generation = generation
        source = key.remote
        destination = key.local
        self.output = output
        self.ready = ready
        self.removed = removed
        self.schedule = schedule
        self.delayAcknowledgment = delayAcknowledgment
        self.clock = clock
        state = Mutex(State(packet: packet, initialSequenceNumber: initialSequenceNumber, ticks: clock.now, pendingLimit: pendingLimit, delaysAcknowledgment: delaysAcknowledgment))
    }

    private func update<T: Sendable>(_ body: (inout State) -> T) -> T {
        let (result, drain, previous, deadline) = state.withLock { state in
            state.core.stack.advance(to: clock.now)
            let result = body(&state)
            state.harvest()
            state.observeArena()
            if state.core.acknowledgmentHeld, !state.acknowledgmentQueued {
                state.acknowledgmentQueued = true
                state.publications.append(.delayAcknowledgment)
            }
            let drain = !state.draining && !state.publications.isEmpty
            if drain { state.draining = true }
            let deadline = state.deadline.map { $0 == 0 ? 1 : $0 } ?? 0
            let previous = scheduled.exchange(deadline, ordering: .sequentiallyConsistent)
            lingering.store(state.core.state == .timeWait || state.core.state == .closed, ordering: .relaxed)
            return (result, drain, previous, deadline)
        }
        if drain { drainPublications() }
        if deadline != 0, previous == 0 || Sequence.lessThan(deadline, previous) { schedule(deadline) }
        return result
    }

    private func drainPublications() {
        var batch: [Publication] = []
        while true {
            state.withLock { state in
                swap(&batch, &state.publications)
                if batch.isEmpty { state.draining = false }
            }
            if batch.isEmpty { return }
            var packets: [OutboundPacket] = []
            for publication in batch {
                if case .output(let packet) = publication { packets.append(packet); continue }
                if !packets.isEmpty { output(packets); packets.removeAll(keepingCapacity: true) }
                switch publication {
                case .output: break
                case .ready: ready(PendingConnection(stream: self))
                case .remove: removed(self)
                case .delayAcknowledgment: delayAcknowledgment(self)
                case .wake(let continuation): continuation.resume()
                }
            }
            if !packets.isEmpty { output(packets) }
            batch.removeAll(keepingCapacity: true)
        }
    }

    private func perform<Value: Sendable>(_ role: Role, _ step: (inout State) -> Outcome<Value>) async throws -> Value {
        var claimed = false
        defer {
            if claimed { state.withLock { $0.withWaiter(role) { $0.hold(false) } } }
        }
        while true {
            try Task.checkCancellation()
            let outcome = update { state -> Outcome<Value> in
                if !claimed {
                    guard !state.withWaiter(role, { $0.isBusy }) else { return .failure(.concurrentOperation) }
                    claimed = true
                }
                let outcome = step(&state)
                claimed = outcome.isWaiting
                state.withWaiter(role) { $0.hold(claimed) }
                return outcome
            }
            switch outcome {
            case .finished(let value): return value
            case .failure(let error): throw error
            case .wait: await park(role)
            }
        }
    }

    private func park(_ role: Role) async {
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let parked = state.withLock { state in
                    state.withWaiter(role) { waiter in waiter.park(continuation) }
                }
                if !parked { continuation.resume() }
            }
        } onCancel: {
            state.withLock { state in
                state.withWaiter(role) { waiter in waiter.signal() }
            }?.resume()
        }
    }

    func input(_ packet: InboundTCP) {
        _ = inputBatch([packet][...])
    }

    func inputBatch(_ packets: ArraySlice<InboundTCP>) -> Int {
        update { state in
            let core = state.core
            core.stack.batching = true
            var processed = 0
            for packet in packets {
                guard core.state != .closed else { break }
                processed += 1
                if !state.started {
                    state.started = true
                    core.sendSynAck()
                    if packet.header.flags.contains(.syn) { continue }
                }
                if core.state == .timeWait {
                    core.timeWaitInput(header: packet.header, payloadCount: packet.payload.count)
                } else {
                    core.input(header: packet.header, options: packet.options, payload: packet.payload)
                }
                state.harvest()
            }
            core.stack.batching = false
            state.harvest()
            state.pump()
            return processed
        }
    }

    func flushAcknowledgment() {
        update { state in
            state.acknowledgmentQueued = false
            state.core.flushHeldAcknowledgment()
        }
    }

    func expire() -> UInt32 {
        update { state in
            let ticks = state.core.stack.ticks
            if let since = state.reclaimableSince, ticks &- since >= Constants.arenaReclaimDelay {
                state.core.arena.reclaim()
                state.reclaimableSince = nil
            }
            if let since = state.input.unsealedSince, ticks &- since >= Constants.receiveSealDelay {
                state.input.seal()
                state.wakeReaders()
            }
            guard state.core.state != .closed else { return }
            if state.core.state == .timeWait {
                if ticks &- state.core.tmr > Constants.timeWaitTimeout {
                    state.core.state = .closed
                    state.publications.append(.remove)
                    state.finish(nil)
                }
            } else if case .pending = state.admission,
                      ticks &- state.admissionTick > Constants.synReceivedTimeout {
                state.core.terminate(sendingReset: true, error: .aborted)
            } else {
                state.core.slowTick(ticks: ticks)
                state.harvest()
                state.pump()
            }
        }
        return scheduledDeadline
    }

    func resolve(_ verdict: AcceptVerdict) -> Bool {
        update { state in
            guard case .pending = state.admission, !state.ended else { return false }
            switch verdict {
            case .accept:
                state.admission = .accepted
                if let packet = state.deferredAcknowledgment { state.publications.append(.output(packet)) }
                state.deferredAcknowledgment = nil
                state.wakeReaders()
            case .drop, .reset:
                state.admission = .rejected
                state.core.terminate(sendingReset: verdict == .reset, error: .aborted)
                state.finish(.aborted)
            }
            return true
        }
    }

    func reclaimIfClosing() -> Bool {
        update { state in
            switch state.core.state {
            case .timeWait, .lastAck, .closing:
                state.core.terminate(sendingReset: false, error: .aborted)
                state.finish(.aborted)
                return true
            default: return false
            }
        }
    }

    @discardableResult public func enqueue(_ data: Data) -> Bool {
        guard !data.isEmpty else { return true }
        return update { state in
            guard !state.ended, !state.closing, !state.sendingFinished, !state.writer.isBusy,
                  case .accepted = state.admission,
                  data.count <= state.pendingLimit - state.pendingBytes else { return false }
            state.pending.append(data)
            state.pendingBytes += data.count
            state.pump()
            return true
        }
    }

    public func send(_ data: Data) async throws {
        var offset = 0
        try await perform(.writer) { $0.write(data, from: &offset) }
    }

    public func receive() async throws -> Data? {
        try await perform(.reader) { $0.read() }
    }

    public func didConsume(_ byteCount: Int) {
        guard byteCount > 0 else { return }
        update { state in
            let consumed = min(byteCount, state.deliveredBytes)
            state.deliveredBytes -= consumed
            state.core.didConsume(consumed)
            state.core.output()
        }
    }

    public func finishSending() {
        update { state in
            state.sendingFinished = true
            state.pump()
        }
    }

    public func waitUntilAcknowledged() async throws {
        try await perform(.acknowledger) { $0.acknowledgment() }
    }

    public func close(discardingReceived: Bool = false) {
        update { state in
            guard !state.ended, !state.closing else { return }
            state.closing = true
            if discardingReceived {
                let unread = state.input.unreadByteCount + state.deliveredBytes
                state.deliveredBytes = 0
                state.core.didConsume(unread)
            }
            state.input.removeAll()
            state.pump()
            state.wakeReaders(); state.wakeWriters()
        }
    }

    public func cancel() { terminate(sendingReset: true) }

    public func discard() { terminate(sendingReset: false) }

    private func terminate(sendingReset: Bool) {
        update { state in
            state.core.terminate(sendingReset: sendingReset, error: .aborted)
            state.finish(.aborted)
        }
    }
}
