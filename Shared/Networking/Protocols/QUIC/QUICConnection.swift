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

    enum QUICError: Error, LocalizedError {
        case connectionFailed(String)
        case handshakeFailed(String)
        case streamError(String)
        /// Peer sent RESET_STREAM (read side aborted).
        case streamReset(appErrorCode: UInt64)
        /// `stream_close` fired with an application error code set.
        case streamClosedWithError(appErrorCode: UInt64)
        /// Queued DATAGRAM exceeded the path's max frame size and was dropped; re-fragment to `maxBound` for a retry.
        case datagramTooLarge(maxBound: Int)
        /// An atomic DATAGRAM batch did not fit the bounded send queue. Nothing
        /// from that batch was enqueued and the existing queue was unchanged.
        case datagramQueueFull
        case timeout
        case closed
        /// Peer closed the whole connection with a benign code (transport NO_ERROR, or
        /// application H3_NO_ERROR / `closeErrCodeOK` 0x100).
        case closedOK

        var errorDescription: String? {
            switch self {
            case .connectionFailed(let m): return "QUIC: \(m)"
            case .handshakeFailed(let m): return "QUIC TLS: \(m)"
            case .streamError(let m): return "QUIC stream: \(m)"
            case .streamReset(let c): return "QUIC stream reset (app code \(c))"
            case .streamClosedWithError(let c): return "QUIC stream closed (app code \(c))"
            case .datagramTooLarge(let b): return "QUIC datagram exceeds path MTU (max \(b) B)"
            case .datagramQueueFull: return "QUIC datagram send queue is full"
            case .timeout: return "QUIC timeout"
            case .closed: return "QUIC closed"
            case .closedOK: return "QUIC closed (OK)"
            }
        }
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
    
    var carrier: QUICDatagramCarrier?
    
    var transportReceiveTask: Task<Void, Never>?
    
    var transportSealContinuation: AsyncStream<Data>.Continuation?
    var transportSealTask: Task<Void, Never>?

    var localAddr = sockaddr_storage()
    var remoteAddr = sockaddr_storage()
    var addrLen: Int = MemoryLayout<sockaddr_in>.size

    // MARK: Migration state (direct carrier only; all touched on `queue`)

    enum MigrationKind { case reactive, proactive }
    /// Set while a path switch is in flight (awaiting ngtcp2 path validation).
    var migrationKind: MigrationKind?
    /// Proactive-migration target, live alongside `carrier` until the new path
    /// validates. `nil` for reactive (the dead carrier is retired at once).
    var migratingCarrier: QUICDatagramCarrier?
    /// Distinct cosmetic local addr of the migration target path, so ngtcp2 sees a
    /// path change and `writeToUDP` can route per path during proactive validation.
    var migratingLocalAddr = sockaddr_storage()
    /// Monotonic source of distinct cosmetic local addrs across migrations.
    var migrationCounter: UInt8 = 0
    /// Genuine migration failures (ngtcp2 rejected, or path didn't validate) since the
    /// last success — a signal the server can't migrate. Benign aborts don't count.
    var migrationFailures = 0
    static let maxMigrationFailures = 3
    /// True once a proactive migration called `initiate_migration` and ngtcp2 owns a
    /// validation only `path_validation` can resolve. Gates eager aborts mid-probe.
    var proactiveValidating = false
    /// Fires if a proactive target never becomes ready; bounds the in-flight state.
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
    
    var pendingWrites: [PendingWrite] = []

    struct PendingWrite {
        let streamId: Int64
        var data: Data
        let fin: Bool
        let continuation: CheckedContinuation<Void, Error>?
    }
    
    var inflightStreamBuffers: [Int64: [InflightStreamBuffer]] = [:]
    
    var streamTxOffset: [Int64: UInt64] = [:]

    /// Stable heap copy of stream bytes handed to ngtcp2.
    final class InflightStreamBuffer {
        let storage: UnsafeMutableBufferPointer<UInt8>
        var endOffset: UInt64 = 0

        init(copying data: Data) {
            let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: data.count)
            _ = data.copyBytes(to: buffer)
            storage = buffer
        }

        deinit { storage.deallocate() }
        
        func withStableBase<R>(_ body: (UnsafeMutablePointer<UInt8>) -> R) -> R {
            body(storage.baseAddress!)
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
