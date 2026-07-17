//
//  TLSRecordConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation
import CryptoKit
import CommonCrypto
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "TLSRecordConnection")

nonisolated final class TLSRecordConnection: Sendable {

    // MARK: Properties

    /// The underlying async byte transport, held in a mutex so the abortive nil-swap in
    /// ``cancel()`` is atomic against the in-flight sends/receives that read it. The transport
    /// reference is the real critical state; access it through the ``connection`` computed
    /// property or, for the atomic take-and-clear, ``connectionBox`` directly.
    private let connectionBox = Mutex<(any ByteTransport)?>(nil)

    /// The underlying async byte transport. `nil` after ``cancel()``. Every write is serialized
    /// through the send chain so records reach the wire in submission order.
    var connection: (any ByteTransport)? {
        get { connectionBox.withLock { $0 } }
        set { connectionBox.withLock { $0 = newValue } }
    }

    /// Ordered wire-send pipeline shared by the async `send`/`sendRaw` surface and the internal
    /// TLS 1.3 KeyUpdate response. Each ``chainedSend`` body runs only once the previous finished,
    /// so record building (sequence-number assignment) and the key-switch never interleave a send —
    /// submission order is wire order — without a lock held across the `await`.
    private let sendChain = SerialSender()

    /// Runs `body` after all prior chained sends and awaits it (backpressure + errors). Internal so
    /// the +TLS13 KeyUpdate response (a different file) drains through the same chain.
    func chainedSend(_ body: @escaping @Sendable () async throws -> Void) async throws {
        try await sendChain.run(body)
    }

    let tlsVersion: UInt16

    /// Backing store for ``negotiatedALPN``; the mutex makes the handshake-time write a safe
    /// publication to whichever task later reads it.
    private let negotiatedALPNBox = Mutex<String>("")

    /// The value of the ALPN sent by the peer; empty when the peer selected none. Written once
    /// by the handshake driver (TLSClient/TLSServer/RealityClient), read after.
    var negotiatedALPN: String {
        get { negotiatedALPNBox.withLock { $0 } }
        set { negotiatedALPNBox.withLock { $0 = newValue } }
    }

    let cipherSuite: UInt16

    // MARK: - Per-direction Record State

    /// One direction's record-protection state: the AEAD key material plus that direction's
    /// record sequence counter (a fetch-then-increment per record). The key fields are mutable
    /// only for the TLS 1.3 post-handshake KeyUpdate (RFC 8446 §7.2), which installs the next
    /// key generation AND resets the counter to zero; both live behind one mutex so the epoch
    /// switch is a single atomic mutation — a record can never pair new keys with an old
    /// counter or vice versa.
    struct DirectionState {
        var key: Data
        var iv: Data
        var symmetricKey: SymmetricKey
        /// TLS 1.3 application traffic secret, retained so KeyUpdate can derive the next
        /// generation. `nil` for TLS 1.2 (which has no KeyUpdate) and disables KeyUpdate handling.
        var appSecret: Data? = nil
        /// The AEAD record sequence counter for this direction.
        var seqNum: UInt64 = 0
    }

    /// Egress (our send direction) record state. Reads happen per record build; the rekey
    /// mutation runs only under the send chain, so egress epochs are additionally ordered
    /// against every application send.
    private let egressState: Mutex<DirectionState>

    /// Ingress (peer's send direction) record state. The rekey mutation runs only on the
    /// receive path, which is driven by a single consumer holding the ``receiveState`` lock —
    /// this lock nests inside that one, never the reverse.
    private let ingressState: Mutex<DirectionState>

    /// TLS 1.2 CBC MAC keys, mapped to this endpoint's directions at init. Empty for AEAD
    /// suites and TLS 1.3; immutable — no rekey path exists for them.
    let egressMACKey: Data
    let ingressMACKey: Data

    /// Fetches the egress key generation paired with the sequence number the next record must
    /// be sealed with (`seqNum` of the returned snapshot), post-incrementing the counter. One
    /// lock hold pairs the two, so the pair can never straddle a KeyUpdate epoch switch;
    /// callers compute the record from the snapshot outside the lock.
    func nextEgressState() -> DirectionState {
        egressState.withLock { state in
            defer { state.seqNum += 1 }
            return state
        }
    }

    /// Fetches the ingress key generation paired with the sequence number the next record must
    /// be opened with, post-incrementing the counter (see ``nextEgressState()``).
    func nextIngressState() -> DirectionState {
        ingressState.withLock { state in
            defer { state.seqNum += 1 }
            return state
        }
    }

    /// Runs `mutate` under the egress-state lock — the egress KeyUpdate epoch switch commits
    /// its key swap and counter reset in one hold. `mutate` must not block or await; key
    /// derivation is the intended (short, synchronous) workload.
    func mutateEgressState(_ mutate: (inout DirectionState) -> Void) {
        egressState.withLock { mutate(&$0) }
    }

    /// Runs `mutate` under the ingress-state lock (see ``mutateEgressState(_:)``).
    func mutateIngressState(_ mutate: (inout DirectionState) -> Void) {
        ingressState.withLock { mutate(&$0) }
    }

    private static let maxRecordPlaintext = 16384

    // MARK: - Receive State

    /// The record layer's receive-side critical state: the undecrypted byte buffer plus the
    /// flags the decrypt path latches while draining it. A given connection has a single
    /// receive consumer; `processBuffer` runs with this lock held and mutates the state
    /// through `inout` rather than re-locking.
    struct ReceiveState {
        var buffer: Data
        /// Set when a peer KeyUpdate(update_requested) arrives; consumed after this lock is
        /// released so we can send our own KeyUpdate without holding it.
        var keyUpdateResponsePending = false
        /// Latched when the peer's close_notify arrives; further receives report a clean close.
        var receivedCloseNotify = false
    }

    private let receiveState = Mutex<ReceiveState>(ReceiveState(buffer: Data(capacity: 256 * 1024)))

    // MARK: Initialization

    enum Direction {
        case client
        case server
    }

    let direction: Direction

    init(clientKey: Data, clientIV: Data, serverKey: Data, serverIV: Data,
         cipherSuite: UInt16 = TLSCipherSuite.TLS_AES_128_GCM_SHA256,
         clientAppSecret: Data? = nil, serverAppSecret: Data? = nil,
         direction: Direction = .client) {
        self.tlsVersion = 0x0304
        self.cipherSuite = cipherSuite
        self.direction = direction
        // Map the wire roles (client/server) onto this endpoint's directions once, here; the
        // record paths deal only in egress/ingress.
        let client = DirectionState(key: clientKey, iv: clientIV,
                                    symmetricKey: SymmetricKey(data: clientKey),
                                    appSecret: clientAppSecret)
        let server = DirectionState(key: serverKey, iv: serverIV,
                                    symmetricKey: SymmetricKey(data: serverKey),
                                    appSecret: serverAppSecret)
        self.egressState = Mutex(direction == .server ? server : client)
        self.ingressState = Mutex(direction == .server ? client : server)
        self.egressMACKey = Data()
        self.ingressMACKey = Data()
    }

    init(
        tls12ClientKey clientKey: Data,
        clientIV: Data,
        serverKey: Data,
        serverIV: Data,
        clientMACKey: Data,
        serverMACKey: Data,
        cipherSuite: UInt16,
        protocolVersion: UInt16 = 0x0303,
        initialClientSeqNum: UInt64 = 0,
        initialServerSeqNum: UInt64 = 0,
        direction: Direction = .client
    ) {
        self.tlsVersion = protocolVersion
        self.cipherSuite = cipherSuite
        self.direction = direction
        let client = DirectionState(key: clientKey, iv: clientIV,
                                    symmetricKey: SymmetricKey(data: clientKey),
                                    seqNum: initialClientSeqNum)
        let server = DirectionState(key: serverKey, iv: serverIV,
                                    symmetricKey: SymmetricKey(data: serverKey),
                                    seqNum: initialServerSeqNum)
        self.egressState = Mutex(direction == .server ? server : client)
        self.ingressState = Mutex(direction == .server ? client : server)
        self.egressMACKey = direction == .server ? serverMACKey : clientMACKey
        self.ingressMACKey = direction == .server ? clientMACKey : serverMACKey
    }

    /// Buffers application bytes read during the handshake; call before any `receive()`.
    func prependToReceiveBuffer(_ data: Data) {
        receiveState.withLock { $0.buffer.append(data) }
    }

    // MARK: - Send / Receive (Raw, Unencrypted)

    // Async raw (unencrypted) surface for the VLESS-Vision direct-copy path, which peels the record
    // crypto and shuttles already-framed TLS records straight through. A given connection is driven
    // by one consumer, so this never races the encrypted `receive()` on the receive state.

    /// Sends `data` verbatim (no record encryption), serialized through the send chain so it
    /// orders with the encrypted sends and the internal KeyUpdate response.
    func sendRaw(_ data: Data) async throws {
        try await chainedSend { [self] in
            guard let connection else { throw TLSRecordError.connectionUnavailable }
            try await connection.send(data)
        }
    }

    /// Receives raw (undecrypted) bytes: any handshake-buffered bytes first, then straight off the
    /// transport. `nil` signals a clean close.
    func receiveRaw() async throws -> Data? {
        let buffered: Data? = receiveState.withLock { state in
            guard !state.buffer.isEmpty else { return nil }
            let data = state.buffer
            state.buffer.removeAll()
            return data
        }
        if let buffered { return buffered }

        guard let connection else { throw TLSRecordError.connectionUnavailable }
        switch try await connection.receive() {
        case .bytes(let data): return data
        case .end: return nil
        }
    }

    // MARK: - Async Surface

    // The record layer's send/receive surface, over the transport's async surface
    // (writes serialized through the send chain). Its consumers are `TLSProxyConnection`/
    // `RealityProxyConnection`, the MITM `MITMByteLeg` legs, and the async raw direct-copy above.
    // Sends and the raw direct-copy share the synchronous record crypto and `processBuffer`;
    // a given connection is driven by one consumer, so the receive paths never touch
    // the receive state concurrently.

    /// Encrypts `data` into TLS records and sends them, awaiting the write. The record build
    /// (sequence-number assignment) and the wire send happen under a single the send chain hold,
    /// so a record's sequence number always matches its position on the wire — even under
    /// concurrent callers — and it orders with the internal KeyUpdate response.
    func send(_ data: Data) async throws {
        try await chainedSend { [self] in
            guard let connection else { throw TLSRecordError.connectionUnavailable }
            let record = try buildTLSRecords(for: data)
            try await connection.send(record)
        }
    }

    /// Receives and decrypts one chunk of application data; `nil` signals a clean close.
    func receive() async throws -> Data? {
        while true {
            let (processed, needsKeyUpdateResponse) = receiveState.withLock { state -> (BufferResult?, Bool) in
                let processed = processBuffer(&state)
                let needsKeyUpdateResponse = state.keyUpdateResponsePending
                state.keyUpdateResponsePending = false
                return (processed, needsKeyUpdateResponse)
            }

            if needsKeyUpdateResponse {
                await sendKeyUpdateResponseAndRekeyEgress()
            }

            if let result = processed {
                switch result {
                case .data(let data):
                    return data
                case .error(let error):
                    throw error
                case .needMore:
                    break            // fall through to read more bytes
                case .skip:
                    continue         // re-process without reading (non-app record consumed)
                case .closed:
                    return nil
                }
            }

            guard let connection else {
                throw TLSRecordError.connectionUnavailable
            }
            switch try await connection.receive() {
            case .bytes(let data):
                receiveState.withLock { $0.buffer.append(data) }
                continue             // re-process with the new bytes
            case .end:
                return nil
            }
        }
    }

    // MARK: - Cancel

    func cancel() {
        let transport = connectionBox.withLock { box -> (any ByteTransport)? in
            let transport = box
            box = nil                // in-flight and subsequent sends see nil and abort
            return transport
        }

        receiveState.withLock { $0.buffer.removeAll() }

        transport?.cancel()
    }

    // MARK: - Internal Buffer Processing

    private enum BufferResult {
        case data(Data)
        case error(Error)
        case needMore
        case skip
        case closed
    }

    /// Processes framed records out of `state` (passed `inout` by the single receive consumer,
    /// which holds the ``receiveState`` lock while this runs).
    private func processBuffer(_ state: inout ReceiveState) -> BufferResult? {
        if state.receivedCloseNotify {
            return .closed
        }

        if state.buffer.count == 0 {
            return nil
        }

        var batchedData = Data(capacity: state.buffer.count)
        var hasError: Error? = nil
        var recordsProcessed = 0
        var bytesPendingReplay: Data? = nil

        var consumed = 0

        while state.buffer.count - consumed >= 5 {
            var contentType: UInt8 = 0
            var recordLen: UInt16 = 0

            state.buffer.withUnsafeBytes { pointer in
                let p = pointer.bindMemory(to: UInt8.self)
                contentType = p[consumed]
                recordLen = UInt16(p[consumed + 3]) << 8 | UInt16(p[consumed + 4])
            }

            let maxCiphertext = tlsVersion >= 0x0304 ? 16384 + 256 : 16384 + 2048
            guard Int(recordLen) <= maxCiphertext else {
                state.buffer.removeAll()
                return .error(TLSRecordError.malformedRecord("record overflow (\(recordLen) bytes)"))
            }

            let totalLen = 5 + Int(recordLen)
            guard state.buffer.count - consumed >= totalLen else { break }

            let base = state.buffer.startIndex
            let headerStart = base + consumed
            let headerEnd = headerStart + 5
            let bodyEnd = headerStart + totalLen

            let header = state.buffer[headerStart..<headerEnd]
            let body = state.buffer[headerEnd..<bodyEnd]

            recordsProcessed += 1

            if contentType == TLSContentType.applicationData {
                let ingress = nextIngressState()

                do {
                    let decrypted = try decryptTLSRecord(ciphertext: body, header: header, ingress: ingress, receive: &state)
                    consumed += totalLen
                    if !decrypted.isEmpty {
                        batchedData.append(decrypted)
                    }
                    if state.receivedCloseNotify { break }
                } catch {
                    if case TLSRecordError.tlsAlert = error {
                        state.buffer.removeAll()
                        consumed = 0
                        hasError = error
                        break
                    }
                    let pending = Data(state.buffer[(base + consumed)...])
                    state.buffer.removeAll()
                    consumed = 0
                    bytesPendingReplay = pending
                    hasError = error
                    break
                }
            } else if contentType == TLSContentType.alert {
                if tlsVersion < 0x0304 {
                    let ingress = nextIngressState()

                    consumed += totalLen
                    if let alert = try? decryptTLSRecord(ciphertext: body, header: header, ingress: ingress, receive: &state),
                       alert.count >= 2 {
                        if alert[alert.startIndex + 1] == TLSAlertDescription.closeNotify {
                            state.receivedCloseNotify = true
                        } else {
                            hasError = TLSRecordError.tlsAlert(level: alert[alert.startIndex],
                                                               description: alert[alert.startIndex + 1])
                        }
                    } else {
                        hasError = TLSRecordError.unexpectedAlert
                    }
                } else {
                    consumed += totalLen
                    hasError = TLSRecordError.unexpectedAlert
                }
                break
            } else {
                consumed += totalLen
            }
        }

        if consumed > 0 {
            if consumed >= state.buffer.count {
                state.buffer = Data()
            } else {
                state.buffer = Data(state.buffer.suffix(from: state.buffer.startIndex + consumed))
            }
        }

        if let error = hasError {
            if !batchedData.isEmpty {
                if let pending = bytesPendingReplay {
                    state.buffer = pending
                }
                return .data(batchedData)
            }
            return .error(error)
        }

        if state.receivedCloseNotify {
            if !batchedData.isEmpty {
                return .data(batchedData)
            }
            return .closed
        }

        if !batchedData.isEmpty {
            return .data(batchedData)
        }

        if recordsProcessed > 0 {
            return .skip
        }

        return nil
    }

    // MARK: - TLS Record Crypto (Dispatch)

    private func buildTLSRecords(for data: Data) throws -> Data {
        if data.count <= Self.maxRecordPlaintext {
            return try encryptSingleRecord(plaintext: data, contentType: TLSContentType.applicationData)
        }

        let chunkCount = (data.count + Self.maxRecordPlaintext - 1) / Self.maxRecordPlaintext
        var records = Data(capacity: data.count + chunkCount * 64)
        var offset = 0
        while offset < data.count {
            let end = min(offset + Self.maxRecordPlaintext, data.count)
            records.append(try encryptSingleRecord(plaintext: Data(data[offset..<end]), contentType: TLSContentType.applicationData))
            offset = end
        }
        return records
    }

    private func encryptSingleRecord(plaintext: Data, contentType: UInt8) throws -> Data {
        if tlsVersion >= 0x0304 {
            return try encryptTLS13Record(plaintext: plaintext, contentType: contentType)
        } else {
            return try encryptTLS12Record(plaintext: plaintext, contentType: contentType)
        }
    }

    private func decryptTLSRecord(ciphertext: Data, header: Data, ingress: DirectionState, receive state: inout ReceiveState) throws -> Data {
        if tlsVersion >= 0x0304 {
            return try decryptTLS13Record(ciphertext: ciphertext, header: header, ingress: ingress, receive: &state)
        } else {
            return try decryptTLS12Record(ciphertext: ciphertext, header: header, ingress: ingress)
        }
    }

    // MARK: - AEAD Helpers

    func sealAEAD(plaintext: Data, nonce: Data, aad: Data, key: SymmetricKey) throws -> (ciphertext: Data, tag: Data) {
        if TLSCipherSuite.isChaCha20(cipherSuite) {
            let nonceObj = try ChaChaPoly.Nonce(data: nonce)
            let sealedBox = try ChaChaPoly.seal(plaintext, using: key, nonce: nonceObj, authenticating: aad)
            return (Data(sealedBox.ciphertext), Data(sealedBox.tag))
        } else {
            let nonceObj = try AES.GCM.Nonce(data: nonce)
            let sealedBox = try AES.GCM.seal(plaintext, using: key, nonce: nonceObj, authenticating: aad)
            return (Data(sealedBox.ciphertext), Data(sealedBox.tag))
        }
    }

    func openAEAD(ciphertext: Data, tag: Data, nonce: Data, aad: Data, key: SymmetricKey) throws -> Data {
        do {
            if TLSCipherSuite.isChaCha20(cipherSuite) {
                let nonceObj = try ChaChaPoly.Nonce(data: nonce)
                let sealedBox = try ChaChaPoly.SealedBox(nonce: nonceObj, ciphertext: ciphertext, tag: tag)
                return Data(try ChaChaPoly.open(sealedBox, using: key, authenticating: aad))
            } else {
                let nonceObj = try AES.GCM.Nonce(data: nonce)
                let sealedBox = try AES.GCM.SealedBox(nonce: nonceObj, ciphertext: ciphertext, tag: tag)
                return Data(try AES.GCM.open(sealedBox, using: key, authenticating: aad))
            }
        } catch CryptoKitError.authenticationFailure {
            throw TLSRecordError.recordAuthenticationFailed
        }
    }

    @inline(__always)
    func xorSeqIntoNonce(_ nonce: inout Data, seqNum: UInt64) {
        nonce.withUnsafeMutableBytes { pointer in
            let p = pointer.bindMemory(to: UInt8.self)
            let base = p.count - 8
            for i in 0..<8 {
                p[base + i] ^= UInt8((seqNum >> ((7 - i) * 8)) & 0xFF)
            }
        }
    }
}
