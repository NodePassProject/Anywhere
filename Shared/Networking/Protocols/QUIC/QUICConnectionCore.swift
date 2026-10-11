//
//  QUICConnectionCore.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import Synchronization
import Network
import AnywhereQUIC

nonisolated private let logger = AnywhereLogger(category: "QUICConnection")

// MARK: - QUICPacketObfuscator

nonisolated protocol QUICPacketObfuscator: AnyObject, Sendable {
    func seal(_ packet: UnsafeRawBufferPointer) -> [Data]
    func open(_ datagram: Data) -> Data?
}

// MARK: - QUICConnection

nonisolated final class QUICConnectionCore: QUICPublishingState {
    weak var owner: QUICConnection?
    var publications: [@Sendable () -> Void] = []

    func publish(_ action: @escaping @Sendable () -> Void) { publications.append(action) }

    enum Phase: CustomStringConvertible, PhaseTransitionable {
        case idle, connecting, handshaking, connected, closed

        var description: String {
            switch self {
            case .idle: "idle"
            case .connecting: "connecting"
            case .handshaking: "handshaking"
            case .connected: "connected"
            case .closed: "closed"
            }
        }

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .connecting),
                 (.connecting, .handshaking),
                 (.handshaking, .connected):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }
    }

    // MARK: Properties

    let host: String
    let port: UInt16
    let serverName: String
    let alpn: [String]
    let tuning: QUICTuning
    let directMaxUDPPayload: Int

    let transport: QUICDatagramTransport?

    let obfuscator: QUICPacketObfuscator?

    let executor: BridgeExecutor

    private(set) var phase: Phase = .idle

    @discardableResult
    func transition(to new: Phase) -> Bool {
        let old = phase
        guard Phase.transition(&phase, to: new) else {
            if new != .closed {
                logger.error("[QUIC] Invalid transition \(old) → \(new) for \(host); ignored")
            }
            return false
        }
        return true
    }

    var engine: AnywhereQUIC.QUICConnection?

    var eventBuffer: [QUICEvent] = []

    var flushScheduled = false

    var carrier: QUICDatagramCarrier?

    var rootTask: Task<Void, Never>?

    var transportSealContinuation: AsyncStream<Data>.Continuation?

    var localAddr = sockaddr_storage()
    var remoteAddr = sockaddr_storage()
    var addrLen: Int = MemoryLayout<sockaddr_in>.size

    // MARK: Migration state

    enum Migration: PhaseTransitionable {
        case none
        case proactiveProbing(target: QUICDatagramCarrier, localAddr: sockaddr_storage)
        case proactiveValidating(target: QUICDatagramCarrier, localAddr: sockaddr_storage)
        case reactiveValidating(localAddr: sockaddr_storage)

        var label: String {
            switch self {
            case .none: "none"
            case .proactiveProbing: "proactiveProbing"
            case .proactiveValidating: "proactiveValidating"
            case .reactiveValidating: "reactiveValidating"
            }
        }

        static func canTransition(from old: Migration, to new: Migration) -> Bool {
            switch (old, new) {
            case (_, .none),
                 (.none, .proactiveProbing),
                 (.none, .reactiveValidating),
                 (.proactiveProbing, .proactiveValidating):
                return true
            default:
                return false
            }
        }
    }
    var migration: Migration = .none
    var migrationCounter: UInt8 = 0
    var migrationFailures = 0
    static let maxMigrationFailures = 3
    var proactiveDeadlineToken: DeadlineToken?
    static let proactiveReadyTimeout: TimeInterval = 5

    var retransmitTimer: BridgeDeadlineTimer?

    var coarseTimerToken: DeadlineToken?

    static let coarseTimeoutHorizon: UInt64 = 5_000_000_000
    static let promptTimeoutHorizon: UInt64 = 1_000_000_000

    var connectContinuation: CheckedContinuation<Void, Error>?

    var dialAttempt: ConnectionMetrics.Attempt?

    typealias StreamTerminationCause = QUICConnection.StreamTerminationCause
    let handlers: QUICHandlerStore
    var usesBrutalCC = false

    let datagramsEnabled: Bool
    static let maxDatagramFrameSize: UInt64 = 65535

    var streamSendQueues: [Int64: StreamSendQueue] = [:]
    var blockedStreams: Set<Int64> = []

    final class StreamSendChunk {
        let data: Data
        let fin: Bool
        var offset = 0
        var continuation: CheckedContinuation<Void, Error>?

        init(data: Data, fin: Bool, continuation: CheckedContinuation<Void, Error>?) {
            self.data = data
            self.fin = fin
            self.continuation = continuation
        }
    }

    final class StreamSendQueue {
        var chunks: [StreamSendChunk] = []
        var finQueued = false
        var isFailed = false

        func append(_ chunk: StreamSendChunk) {
            chunks.append(chunk)
            if chunk.fin { finQueued = true }
        }

        func fail() -> [CheckedContinuation<Void, Error>] {
            isFailed = true
            let continuations = chunks.compactMap(\.continuation)
            chunks.removeAll()
            return continuations
        }
    }

    struct PendingDatagram {
        let data: Data
        let latch: DatagramBatchLatch?
    }
    var pendingDatagrams: [PendingDatagram] = []
    static let maxPendingDatagrams = 1024
    static let maxQueuedTransportDatagrams = 512

    final class DatagramBatchLatch {
        private var remaining: Int
        private var firstError: Error?
        private var continuation: CheckedContinuation<Void, Error>?

        init(count: Int, continuation: CheckedContinuation<Void, Error>) {
            self.remaining = count
            self.continuation = continuation
        }

        func settle(_ error: Error?) {
            if let error, firstError == nil { firstError = error }
            remaining -= 1
            guard remaining <= 0, let continuation else { return }
            self.continuation = nil
            if let firstError { continuation.resume(throwing: firstError) } else { continuation.resume() }
        }
    }
    var didWarnDatagramOverflow = false

    static let maxUDPPayload = 1452
    static let chainedMaxUDPPayload = 1200

    final class DatagramStage {
        typealias Run = (carrier: QUICDatagramCarrier?, datagrams: [Data])

        private static let packetsPerChunk = 16
        private let packetCapacity: Int
        private let chunkCapacity: Int
        private var chunk: UnsafeMutableRawPointer?
        private var used = 0
        private var staged: [(range: Range<Int>, carrier: QUICDatagramCarrier?)] = []
        private var runs: [Run] = []

        init(packetCapacity: Int) {
            self.packetCapacity = packetCapacity
            chunkCapacity = packetCapacity * Self.packetsPerChunk
        }

        deinit {
            free(chunk)
        }

        func write(_ body: (UnsafeMutableBufferPointer<UInt8>) -> QUICOutgoingDatagram?) -> QUICOutgoingDatagram? {
            if used + packetCapacity > chunkCapacity { seal() }
            let base = chunk ?? allocateChunk()
            return body(UnsafeMutableRawBufferPointer(start: base + used, count: packetCapacity).bindMemory(to: UInt8.self))
        }

        func commit(_ count: Int, to carrier: QUICDatagramCarrier?) {
            staged.append((used..<used + count, carrier))
            used += count
        }

        func takeRuns() -> [Run] {
            seal()
            let result = runs
            runs = []
            return result
        }

        private func allocateChunk() -> UnsafeMutableRawPointer {
            let chunk = malloc(chunkCapacity)!
            self.chunk = chunk
            return chunk
        }

        private func seal() {
            guard let chunk, !staged.isEmpty else { return }
            let data = Data(bytesNoCopy: chunk, count: used, deallocator: .free)
            self.chunk = nil
            used = 0
            for entry in staged {
                let datagram = data[entry.range]
                if let last = runs.last, last.carrier === entry.carrier {
                    runs[runs.count - 1].datagrams.append(datagram)
                } else {
                    runs.append((entry.carrier, [datagram]))
                }
            }
            staged.removeAll(keepingCapacity: true)
        }
    }

    var outbound: DatagramStage?

    static let pmtudProbes: [UInt16] = [1350, 1400, 1452]

    init(
        host: String,
        port: UInt16,
        serverName: String? = nil,
        alpn: [String],
        datagramsEnabled: Bool = false,
        tuning: QUICTuning,
        obfuscator: QUICPacketObfuscator? = nil,
        directMaxUDPPayload: Int = QUICConnectionCore.maxUDPPayload,
        transport: QUICDatagramTransport? = nil,
        handlers: QUICHandlerStore,
        executor: BridgeExecutor
    ) {
        self.handlers = handlers
        self.executor = executor
        self.host = host
        self.port = port
        self.serverName = serverName ?? host
        self.alpn = alpn
        self.datagramsEnabled = datagramsEnabled
        self.tuning = tuning
        self.obfuscator = obfuscator
        self.directMaxUDPPayload = directMaxUDPPayload
        self.transport = transport
    }

    deinit {
        rootTask?.cancel()
        retransmitTimer?.cancel()
        coarseTimerToken?.cancel()
        proactiveDeadlineToken?.cancel()
    }

    var lastScheduledExpiry: UInt64 = 0

    func currentTimestamp() -> QUICInstant {
        QUICInstant(nanoseconds: MonotonicClock.nanoseconds)
    }

    func quicPath(local: sockaddr_storage) -> QUICPath {
        QUICPath(
            local: QUICSocketAddress(local, length: addrLen),
            remote: QUICSocketAddress(remoteAddr, length: addrLen)
        )
    }
}
