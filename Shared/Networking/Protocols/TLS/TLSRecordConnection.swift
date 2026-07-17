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

nonisolated class TLSRecordConnection {

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

    /// Tail of the wire-send chain shared by the async `send`/`sendRaw` surface and the internal
    /// TLS 1.3 KeyUpdate response. Each ``chainedSend`` body runs only once the previous finished,
    /// so record building (sequence-number assignment) and the key-switch never interleave a send —
    /// submission order is wire order — without a lock held across the `await`.
    private let sendChain = SerialSendChain()

    /// Links `body` after all prior chained sends and awaits it (backpressure + errors). Internal so
    /// the +TLS13 KeyUpdate response (a different file) drains through the same chain.
    func chainedSend(_ body: @escaping @Sendable () async throws -> Void) async throws {
        try await sendChain.run(body)
    }

    let tlsVersion: UInt16

    /// The value of the ALPN sent by the peer; empty when the peer selected none.
    var negotiatedALPN: String = ""

    // Mutable so a TLS 1.3 post-handshake KeyUpdate (RFC 8446 §7.2) can install the next
    // key generation. Egress (`*Key`/`*IV` for our send direction) is only mutated under
    // the send chain; ingress (our read direction) only from the receive path. See `rekeyIngress`.
    var clientKey: Data
    var clientIV: Data
    var serverKey: Data
    var serverIV: Data

    private let clientMACKey: Data
    private let serverMACKey: Data

    let cipherSuite: UInt16

    var clientSymmetricKey: SymmetricKey
    var serverSymmetricKey: SymmetricKey

    /// TLS 1.3 application traffic secrets, retained so KeyUpdate can derive the next
    /// generation. `nil` for TLS 1.2 (which has no KeyUpdate) and disables KeyUpdate handling.
    var clientAppSecret: Data?
    var serverAppSecret: Data?

    /// Set on the receive path when a peer KeyUpdate(update_requested) arrives; consumed after
    /// the `receiveBuffer` lock is released so we can send our own KeyUpdate without holding it.
    var keyUpdateResponsePending = false

    /// The per-direction AEAD record sequence counters. These are the true critical state:
    /// each send/receive does a read-modify-write (fetch-then-increment), and a TLS 1.3
    /// KeyUpdate resets one direction to zero. They live inside the mutex so the RMW is atomic
    /// rather than being guarded by a bare lock. Egress writes are additionally ordered by
    /// the send chain and ingress by the single reader, so the counters never race across
    /// directions — the mutex covers the same-direction RMW.
    struct SeqNumbers {
        var client: UInt64 = 0
        var server: UInt64 = 0
    }
    private let seqNums: Mutex<SeqNumbers>

    /// Fetches and post-increments the egress (our send direction) record sequence number.
    func nextEgressSeqNum() -> UInt64 {
        seqNums.withLock { s in
            if direction == .server { defer { s.server += 1 }; return s.server }
            else { defer { s.client += 1 }; return s.client }
        }
    }

    /// Fetches and post-increments the ingress (peer's send direction) record sequence number.
    func nextIngressSeqNum() -> UInt64 {
        seqNums.withLock { s in
            if direction == .server { defer { s.client += 1 }; return s.client }
            else { defer { s.server += 1 }; return s.server }
        }
    }

    /// Resets the egress counter to zero on a TLS 1.3 egress KeyUpdate epoch switch.
    func resetEgressSeqNum() {
        seqNums.withLock { s in if direction == .server { s.server = 0 } else { s.client = 0 } }
    }

    /// Resets the ingress counter to zero on a TLS 1.3 ingress KeyUpdate epoch switch.
    func resetIngressSeqNum() {
        seqNums.withLock { s in if direction == .server { s.client = 0 } else { s.server = 0 } }
    }

    private var sentCloseNotify = false

    private static let maxRecordPlaintext = 16384

    /// The undecrypted receive buffer — the record layer's real receive-side critical state.
    /// Held inside the mutex rather than guarded by a bare lock; every access runs under this
    /// lock, and a given connection has a single receive consumer.
    private let receiveBuffer = Mutex<Data>(Data(capacity: 256 * 1024))

    var receivedCloseNotify = false

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
        self.clientKey = clientKey
        self.clientIV = clientIV
        self.serverKey = serverKey
        self.serverIV = serverIV
        self.clientMACKey = Data()
        self.serverMACKey = Data()
        self.cipherSuite = cipherSuite
        self.clientSymmetricKey = SymmetricKey(data: clientKey)
        self.serverSymmetricKey = SymmetricKey(data: serverKey)
        self.clientAppSecret = clientAppSecret
        self.serverAppSecret = serverAppSecret
        self.direction = direction
        self.seqNums = Mutex(SeqNumbers())
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
        self.clientKey = clientKey
        self.clientIV = clientIV
        self.serverKey = serverKey
        self.serverIV = serverIV
        self.clientMACKey = clientMACKey
        self.serverMACKey = serverMACKey
        self.cipherSuite = cipherSuite
        self.clientSymmetricKey = SymmetricKey(data: clientKey)
        self.serverSymmetricKey = SymmetricKey(data: serverKey)
        self.direction = direction
        self.seqNums = Mutex(SeqNumbers(client: initialClientSeqNum, server: initialServerSeqNum))
    }

    /// Buffers application bytes read during the handshake; call before any `receive()`.
    func prependToReceiveBuffer(_ data: Data) {
        receiveBuffer.withLock { $0.append(data) }
    }

    // MARK: - Direction-aware Key/IV Selection

    var egressKey: Data { direction == .server ? serverKey : clientKey }
    var egressIV: Data { direction == .server ? serverIV : clientIV }
    var egressSymmetricKey: SymmetricKey {
        direction == .server ? serverSymmetricKey : clientSymmetricKey
    }
    var egressMACKey: Data { direction == .server ? serverMACKey : clientMACKey }

    var ingressKey: Data { direction == .server ? clientKey : serverKey }
    var ingressIV: Data { direction == .server ? clientIV : serverIV }
    var ingressSymmetricKey: SymmetricKey {
        direction == .server ? clientSymmetricKey : serverSymmetricKey
    }
    var ingressMACKey: Data { direction == .server ? clientMACKey : serverMACKey }

    // MARK: - Send / Receive (Raw, Unencrypted)

    // Async raw (unencrypted) surface for the VLESS-Vision direct-copy path, which peels the record
    // crypto and shuttles already-framed TLS records straight through. A given connection is driven
    // by one consumer, so this never races the encrypted `receive()` on `receiveBuffer`.

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
        let buffered: Data? = receiveBuffer.withLock { buffer in
            guard !buffer.isEmpty else { return nil }
            let data = buffer
            buffer.removeAll()
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
    // `receiveBuffer` concurrently.

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
            let (processed, needsKeyUpdateResponse) = receiveBuffer.withLock { buffer -> (BufferResult?, Bool) in
                let processed = processBuffer(&buffer)
                let needsKeyUpdateResponse = keyUpdateResponsePending
                keyUpdateResponsePending = false
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
                receiveBuffer.withLock { $0.append(data) }
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

        receiveBuffer.withLock { $0.removeAll() }

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

    /// Processes framed records out of `buffer` (the mutex-guarded receive buffer, passed in
    /// by the single receive consumer under the ``receiveBuffer`` lock).
    private func processBuffer(_ buffer: inout Data) -> BufferResult? {
        if receivedCloseNotify {
            return .closed
        }

        if buffer.count == 0 {
            return nil
        }

        var batchedData = Data(capacity: buffer.count)
        var hasError: Error? = nil
        var recordsProcessed = 0
        var bytesPendingReplay: Data? = nil

        var consumed = 0

        while buffer.count - consumed >= 5 {
            var contentType: UInt8 = 0
            var recordLen: UInt16 = 0

            buffer.withUnsafeBytes { pointer in
                let p = pointer.bindMemory(to: UInt8.self)
                contentType = p[consumed]
                recordLen = UInt16(p[consumed + 3]) << 8 | UInt16(p[consumed + 4])
            }

            let maxCiphertext = tlsVersion >= 0x0304 ? 16384 + 256 : 16384 + 2048
            guard Int(recordLen) <= maxCiphertext else {
                buffer.removeAll()
                return .error(TLSRecordError.malformedRecord("record overflow (\(recordLen) bytes)"))
            }

            let totalLen = 5 + Int(recordLen)
            guard buffer.count - consumed >= totalLen else { break }

            let base = buffer.startIndex
            let headerStart = base + consumed
            let headerEnd = headerStart + 5
            let bodyEnd = headerStart + totalLen

            let header = buffer[headerStart..<headerEnd]
            let body = buffer[headerEnd..<bodyEnd]

            recordsProcessed += 1

            if contentType == TLSContentType.applicationData {
                let seqNum = nextIngressSeqNum()

                do {
                    let decrypted = try decryptTLSRecord(ciphertext: body, header: header, seqNum: seqNum)
                    consumed += totalLen
                    if !decrypted.isEmpty {
                        batchedData.append(decrypted)
                    }
                    if receivedCloseNotify { break }
                } catch {
                    if case TLSRecordError.tlsAlert = error {
                        buffer.removeAll()
                        consumed = 0
                        hasError = error
                        break
                    }
                    let pending = Data(buffer[(base + consumed)...])
                    buffer.removeAll()
                    consumed = 0
                    bytesPendingReplay = pending
                    hasError = error
                    break
                }
            } else if contentType == TLSContentType.alert {
                if tlsVersion < 0x0304 {
                    let seqNum = nextIngressSeqNum()

                    consumed += totalLen
                    if let alert = try? decryptTLSRecord(ciphertext: body, header: header, seqNum: seqNum),
                       alert.count >= 2 {
                        if alert[alert.startIndex + 1] == TLSAlertDescription.closeNotify {
                            receivedCloseNotify = true
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
            if consumed >= buffer.count {
                buffer = Data()
            } else {
                buffer = Data(buffer.suffix(from: buffer.startIndex + consumed))
            }
        }

        if let error = hasError {
            if !batchedData.isEmpty {
                if let pending = bytesPendingReplay {
                    buffer = pending
                }
                return .data(batchedData)
            }
            return .error(error)
        }

        if receivedCloseNotify {
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

    private func decryptTLSRecord(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
        if tlsVersion >= 0x0304 {
            return try decryptTLS13Record(ciphertext: ciphertext, header: header, seqNum: seqNum)
        } else {
            return try decryptTLS12Record(ciphertext: ciphertext, header: header, seqNum: seqNum)
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
