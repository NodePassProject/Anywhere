//
//  QUICConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import Network
import CryptoKit
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "QUICConnection")

// MARK: - QUICPacketObfuscator

nonisolated protocol QUICPacketObfuscator: AnyObject, Sendable {
    /// Transforms one outgoing QUIC datagram into one or more wire datagrams.
    func seal(_ packet: UnsafeRawBufferPointer) -> [Data]

    /// Transforms one received wire datagram into a complete QUIC datagram.
    func open(_ datagram: Data) -> Data?
}

// MARK: - QUICConnection

actor QUICConnection: NGTCP2BridgeHost {

    nonisolated var unownedExecutor: UnownedSerialExecutor {
        bridge.executor.asUnownedSerialExecutor()
    }

    enum State {
        case idle, connecting, handshaking, connected, closing, closed
    }

    // MARK: Properties

    let host: String
    let port: UInt16
    let serverName: String
    let alpn: [String]
    let tuning: QUICTuning
    
    let transport: QUICDatagramTransport?
    
    let obfuscator: QUICPacketObfuscator?

    var state: State = .idle
    
    let bridge: NGTCP2ConcurrencyBridge
    
    nonisolated func enqueue(_ work: @escaping @convention(block) @Sendable () -> Void) {
        bridge.enqueue(work)
    }
    
    nonisolated func run<T>(_ body: @escaping () -> T) async -> T {
        await bridge.run(body)
    }
    
    nonisolated func run<T>(_ body: @escaping () -> Result<T, Error>) async throws -> T {
        try await bridge.run(body).get()
    }

    var connectionOpaquePointer: OpaquePointer?
    var connRefStorage = ngtcp2_crypto_conn_ref()
    
    var inReadPkt = false

    var flushScheduled = false
    
    struct PendingStreamDelivery {
        var data = Data()
        var fin = false

        mutating func append(_ chunk: Data, fin sawFin: Bool) {
            if !chunk.isEmpty { data.append(chunk) }
            if sawFin { fin = true }
        }
    }
    var pendingStreamDeliveries: [Int64: PendingStreamDelivery] = [:]
    var pendingStreamDeliveryOrder: [Int64] = []
    
    var receiveBatchDepth = 0
    
    var carrier: QUICDatagramCarrier?
    
    var rootTask: Task<Void, Never>?
    
    var transportSealContinuation: AsyncStream<Data>.Continuation?

    var localAddr = sockaddr_storage()
    var remoteAddr = sockaddr_storage()
    var addrLen: Int = MemoryLayout<sockaddr_in>.size

    // MARK: Migration state

    enum MigrationKind { case reactive, proactive }
    var migrationKind: MigrationKind?
    var migratingCarrier: QUICDatagramCarrier?
    var migratingLocalAddr = sockaddr_storage()
    var migrationCounter: UInt8 = 0
    var migrationFailures = 0
    static let maxMigrationFailures = 3
    var proactiveValidating = false
    var proactiveDeadlineTask: Task<Void, Never>?
    static let proactiveReadyTimeout: TimeInterval = 5

    var tlsHandler: QUICTLSHandler?
    
    var retransmitTimer: BridgeDeadlineTimer?

    var dcid = ngtcp2_cid()
    var scid = ngtcp2_cid()
    
    var connectContinuation: CheckedContinuation<Void, Error>?
    
    struct Handlers: Sendable {
        var streamData: (@Sendable (Int64, Data, Bool) -> Void)?
        var streamTermination: (@Sendable (Int64, Error?) -> Void)?
        var datagram: (@Sendable (Data) -> Void)?
        var connectionClosed: (@Sendable (Error) -> Void)?
        var bidiCredit: (@Sendable (UInt64) -> Void)?
    }
    let handlers = Mutex(Handlers())

    var brutalCC: BrutalCongestionControl?
    var brutalCCKey: OpaquePointer?

    let datagramsEnabled: Bool
    static let maxDatagramFrameSize: UInt64 = 65535
    
    var streamSendQueues: [Int64: StreamSendQueue] = [:]
    var streamPumpCursor: Int64 = -1
    
    final class StreamSendChunk {
        let storage: UnsafeMutableBufferPointer<UInt8>
        let startOffset: UInt64
        let endOffset: UInt64
        let fin: Bool
        var continuation: CheckedContinuation<Void, Error>?

        init(copying data: Data, at offset: UInt64, fin: Bool,
             continuation: CheckedContinuation<Void, Error>?) {
            let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: max(1, data.count))
            _ = data.copyBytes(to: buffer)
            storage = buffer
            startOffset = offset
            endOffset = offset + UInt64(data.count)
            self.fin = fin
            self.continuation = continuation
        }

        var isBareFin: Bool { startOffset == endOffset }

        deinit { storage.deallocate() }

        func withStableBase<R>(_ body: (UnsafeMutablePointer<UInt8>) -> R) -> R {
            body(storage.baseAddress!)
        }
    }
    
    final class StreamSendQueue {
        var chunks: [StreamSendChunk] = []
        var sentOffset: UInt64 = 0
        var endOffset: UInt64 = 0
        var finQueued = false
        var finSent = false

        var hasUnsent: Bool { sentOffset < endOffset || (finQueued && !finSent) }
        var unsentBytes: Int { Int(endOffset - sentOffset) }
        var bufferedBytes: Int { chunks.reduce(0) { $0 + Int($1.endOffset - $1.startOffset) } }

        func append(_ chunk: StreamSendChunk) {
            chunks.append(chunk)
            endOffset = chunk.endOffset
            if chunk.fin { finQueued = true }
        }
        
        func currentChunk() -> StreamSendChunk? {
            for chunk in chunks {
                if chunk.endOffset > sentOffset { return chunk }
                if chunk.fin, chunk.isBareFin, !finSent, chunk.endOffset == sentOffset {
                    return chunk
                }
            }
            return nil
        }
        
        func advance(accepted: Int, regionLength: Int, finFlagged: Bool) -> [CheckedContinuation<Void, Error>] {
            sentOffset &+= UInt64(accepted)
            if finFlagged && accepted == regionLength { finSent = true }
            var resumed: [CheckedContinuation<Void, Error>] = []
            for chunk in chunks {
                if chunk.endOffset > sentOffset { break }
                guard let continuation = chunk.continuation, !chunk.fin || finSent else { continue }
                chunk.continuation = nil
                resumed.append(continuation)
            }
            return resumed
        }
        
        func trimAcked(upTo ackedOffset: UInt64) {
            var drop = 0
            while drop < chunks.count {
                let chunk = chunks[drop]
                guard chunk.endOffset <= ackedOffset, chunk.continuation == nil,
                      !chunk.fin || finSent else { break }
                drop += 1
            }
            if drop > 0 { chunks.removeFirst(drop) }
        }
        
        func fail() -> [CheckedContinuation<Void, Error>] {
            var failed: [CheckedContinuation<Void, Error>] = []
            for chunk in chunks {
                if let continuation = chunk.continuation {
                    chunk.continuation = nil
                    failed.append(continuation)
                }
            }
            while let last = chunks.last, last.startOffset >= sentOffset {
                chunks.removeLast()
            }
            endOffset = sentOffset
            finQueued = finSent
            return failed
        }
    }
    
    struct PendingDatagram {
        let data: Data
        let latch: DatagramBatchLatch?
    }
    var pendingDatagrams: [PendingDatagram] = []
    static let maxPendingDatagrams = 1024
    
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
    
    var txBuffer = [UInt8](repeating: 0, count: QUICConnection.maxUDPPayload)
    
    var txBatch: [Data] = []
    var txBatchCarrier: QUICDatagramCarrier?
    var txBatchDepth = 0
    
    static let pmtudProbes: [UInt16] = [1350, 1400, 1452]

    // MARK: Init

    nonisolated var isOnQueue: Bool { bridge.isOnQueue }

    init(host: String, port: UInt16, serverName: String? = nil, alpn: [String],
         datagramsEnabled: Bool = false, tuning: QUICTuning,
         obfuscator: QUICPacketObfuscator? = nil,
         transport: QUICDatagramTransport? = nil) {
        self.host = host
        self.port = port
        self.serverName = serverName ?? host
        self.alpn = alpn
        self.datagramsEnabled = datagramsEnabled
        self.tuning = tuning
        self.obfuscator = obfuscator
        self.transport = transport
        self.bridge = NGTCP2ConcurrencyBridge()
    }

    deinit {
        rootTask?.cancel()
    }

    // MARK: Timer state
    
    var lastScheduledExpiry: UInt64 = 0

    // MARK: Utilities

    func currentTimestamp() -> ngtcp2_tstamp {
        ngtcp2_tstamp(DispatchTime.now().uptimeNanoseconds)
    }

    func generateConnectionID(_ cid: inout ngtcp2_cid, length: Int) {
        var data = [UInt8](repeating: 0, count: length)
        _ = SecRandomCopyBytes(kSecRandomDefault, length, &data)
        cid.datalen = length
        withUnsafeMutableBytes(of: &cid.data) { buffer in
            data.withUnsafeBytes { source in
                buffer.copyMemory(from: UnsafeRawBufferPointer(
                    start: source.baseAddress, count: min(length, buffer.count)))
            }
        }
    }
}
