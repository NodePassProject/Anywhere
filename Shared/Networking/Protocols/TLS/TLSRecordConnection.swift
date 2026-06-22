//
//  TLSRecordConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation
import CryptoKit
import CommonCrypto

nonisolated private let logger = AnywhereLogger(category: "TLSRecordConnection")

// MARK: - TLSRecordConnection

nonisolated class TLSRecordConnection {

    // MARK: Properties

    var connection: (any RawTransport)?

    let tlsVersion: UInt16

    /// The value of the ALPN sent by the peer; empty when the peer selected none.
    var negotiatedALPN: String = ""

    // Mutable so a TLS 1.3 post-handshake KeyUpdate (RFC 8446 §7.2) can install the next
    // key generation. Egress (`*Key`/`*IV` for our send direction) is only mutated under
    // `sendLock`; ingress (our read direction) only from the receive path. See `rekeyIngress`.
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
    /// `receiveLock` is released so we can send our own KeyUpdate without holding it.
    var keyUpdateResponsePending = false

    var clientSeqNum: UInt64 = 0
    var serverSeqNum: UInt64 = 0
    let seqLock = UnfairLock()

    let sendLock = UnfairLock()

    private static let maxRecordPlaintext = 16384

    private var receiveBuffer = Data(capacity: 256 * 1024)
    private let receiveLock = UnfairLock()
    
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
        self.clientSeqNum = initialClientSeqNum
        self.serverSeqNum = initialServerSeqNum
        self.clientSymmetricKey = SymmetricKey(data: clientKey)
        self.serverSymmetricKey = SymmetricKey(data: serverKey)
        self.direction = direction
    }

    /// Buffers application bytes read during the handshake; call before any `receive()`.
    func prependToReceiveBuffer(_ data: Data) {
        receiveLock.lock()
        receiveBuffer.append(data)
        receiveLock.unlock()
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

    // MARK: - Send (Encrypted)

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        sendLock.lock()
        guard let connection else {
            sendLock.unlock()
            completion(TLSRecordError.connectionUnavailable)
            return
        }
        do {
            let record = try buildTLSRecords(for: data)
            connection.send(data: record, completion: completion)
            sendLock.unlock()
        } catch {
            sendLock.unlock()
            completion(error)
        }
    }

    func send(data: Data) {
        sendLock.lock()
        guard let connection else {
            sendLock.unlock()
            return
        }
        do {
            let record = try buildTLSRecords(for: data)
            connection.send(data: record)
            sendLock.unlock()
        } catch {
            sendLock.unlock()
        }
    }

    // MARK: - Receive (Encrypted)

    func receive(completion: @escaping (Data?, Error?) -> Void) {
        receiveLock.lock()
        let processed = processBuffer()
        let needsKeyUpdateResponse = keyUpdateResponsePending
        keyUpdateResponsePending = false
        receiveLock.unlock()

        if needsKeyUpdateResponse {
            sendKeyUpdateResponseAndRekeyEgress()
        }

        if let result = processed {
            switch result {
            case .data(let data):
                completion(data, nil)
            case .error(let error):
                completion(nil, error)
            case .needMore:
                fetchMore(completion: completion)
            case .skip:
                self.receive(completion: completion)
            case .closed:
                completion(nil, nil)
            }
            return
        }

        fetchMore(completion: completion)
    }

    // MARK: - Send / Receive (Raw, Unencrypted)

    func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        receiveLock.lock()
        if !receiveBuffer.isEmpty {
            let data = receiveBuffer
            receiveBuffer.removeAll()
            receiveLock.unlock()
            completion(data, nil)
            return
        }
        receiveLock.unlock()

        guard let connection else {
            completion(nil, TLSRecordError.connectionUnavailable)
            return
        }
        connection.receive() { [weak self] data, isComplete, error in
            if let error {
                completion(nil, error)
                return
            }

            guard let data, !data.isEmpty else {
                if isComplete {
                    completion(nil, nil)
                } else {
                    self?.receiveRaw(completion: completion)
                }
                return
            }

            completion(data, nil)
        }
    }

    func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        guard let connection else {
            completion(TLSRecordError.connectionUnavailable)
            return
        }
        connection.send(data: data, completion: completion)
    }

    func sendRaw(data: Data) {
        guard let connection else { return }
        connection.send(data: data)
    }

    // MARK: - Cancel

    func cancel() {
        sendCloseNotify()

        receiveLock.lock()
        receiveBuffer.removeAll()
        receiveLock.unlock()

        connection?.forceCancel()
        connection = nil
    }

    private func sendCloseNotify() {
        sendLock.lock()
        guard let connection else {
            sendLock.unlock()
            return
        }

        do {
            let alertPayload = Data([TLSAlertLevel.warning, TLSAlertDescription.closeNotify])
            let record: Data
            if tlsVersion >= 0x0304 {
                record = try encryptTLS13Record(plaintext: alertPayload, contentType: TLSContentType.alert)
            } else {
                record = try encryptTLS12Record(plaintext: alertPayload, contentType: TLSContentType.alert)
            }
            connection.send(data: record)
            sendLock.unlock()
        } catch {
            sendLock.unlock()
        }
    }

    // MARK: - Internal Buffer Processing

    private enum BufferResult {
        case data(Data)
        case error(Error)
        case needMore
        case skip
        case closed
    }

    private func fetchMore(completion: @escaping (Data?, Error?) -> Void) {
        guard let connection else {
            completion(nil, TLSRecordError.connectionUnavailable)
            return
        }
        connection.receive() { [weak self] data, isComplete, error in
            guard let self else {
                completion(nil, nil)
                return
            }

            if let error {
                completion(nil, error)
                return
            }

            guard let data, !data.isEmpty else {
                if isComplete {
                    completion(nil, nil)
                } else {
                    self.fetchMore(completion: completion)
                }
                return
            }

            self.receiveLock.lock()
            self.receiveBuffer.append(data)
            let processed = self.processBuffer()
            let needsKeyUpdateResponse = self.keyUpdateResponsePending
            self.keyUpdateResponsePending = false
            self.receiveLock.unlock()

            if needsKeyUpdateResponse {
                self.sendKeyUpdateResponseAndRekeyEgress()
            }

            if let result = processed {
                switch result {
                case .data(let data):
                    completion(data, nil)
                case .error(let error):
                    completion(nil, error)
                case .needMore:
                    self.fetchMore(completion: completion)
                case .skip:
                    self.receive(completion: completion)
                case .closed:
                    completion(nil, nil)
                }
            } else {
                self.fetchMore(completion: completion)
            }
        }
    }

    private func processBuffer() -> BufferResult? {
        if receivedCloseNotify {
            return .closed
        }
        
        if receiveBuffer.count == 0 {
            return nil
        }

        var batchedData = Data(capacity: receiveBuffer.count)
        var hasError: Error? = nil
        var recordsProcessed = 0
        var bytesPendingReplay: Data? = nil

        var consumed = 0

        while receiveBuffer.count - consumed >= 5 {
            var contentType: UInt8 = 0
            var recordLen: UInt16 = 0

            receiveBuffer.withUnsafeBytes { pointer in
                let p = pointer.bindMemory(to: UInt8.self)
                contentType = p[consumed]
                recordLen = UInt16(p[consumed + 3]) << 8 | UInt16(p[consumed + 4])
            }

            let maxCiphertext = tlsVersion >= 0x0304 ? 16384 + 256 : 16384 + 2048
            guard Int(recordLen) <= maxCiphertext else {
                receiveBuffer.removeAll()
                return .error(TLSRecordError.malformedRecord("record overflow (\(recordLen) bytes)"))
            }

            let totalLen = 5 + Int(recordLen)
            guard receiveBuffer.count - consumed >= totalLen else { break }

            let base = receiveBuffer.startIndex
            let headerStart = base + consumed
            let headerEnd = headerStart + 5
            let bodyEnd = headerStart + totalLen

            let header = receiveBuffer[headerStart..<headerEnd]
            let body = receiveBuffer[headerEnd..<bodyEnd]

            recordsProcessed += 1

            if contentType == TLSContentType.applicationData {
                seqLock.lock()
                let seqNum: UInt64
                if direction == .server {
                    seqNum = clientSeqNum
                    clientSeqNum += 1
                } else {
                    seqNum = serverSeqNum
                    serverSeqNum += 1
                }
                seqLock.unlock()

                do {
                    let decrypted = try decryptTLSRecord(ciphertext: body, header: header, seqNum: seqNum)
                    consumed += totalLen
                    if !decrypted.isEmpty {
                        batchedData.append(decrypted)
                    }
                    if receivedCloseNotify { break }
                } catch {
                    if case TLSRecordError.tlsAlert = error {
                        receiveBuffer.removeAll()
                        consumed = 0
                        hasError = error
                        break
                    }
                    let pending = Data(receiveBuffer[(base + consumed)...])
                    receiveBuffer.removeAll()
                    consumed = 0
                    bytesPendingReplay = pending
                    hasError = error
                    break
                }
            } else if contentType == TLSContentType.alert {
                if tlsVersion < 0x0304 {
                    seqLock.lock()
                    let seqNum: UInt64
                    if direction == .server {
                        seqNum = clientSeqNum
                        clientSeqNum += 1
                    } else {
                        seqNum = serverSeqNum
                        serverSeqNum += 1
                    }
                    seqLock.unlock()

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
            if consumed >= receiveBuffer.count {
                receiveBuffer = Data()
            } else {
                receiveBuffer = Data(receiveBuffer.suffix(from: receiveBuffer.startIndex + consumed))
            }
        }

        if let error = hasError {
            if !batchedData.isEmpty {
                if let pending = bytesPendingReplay {
                    receiveBuffer = pending
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
        try PerformanceMonitor.measure(.tlsEncrypt) {
            if tlsVersion >= 0x0304 {
                return try encryptTLS13Record(plaintext: plaintext, contentType: contentType)
            } else {
                return try encryptTLS12Record(plaintext: plaintext, contentType: contentType)
            }
        }
    }

    private func decryptTLSRecord(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
        try PerformanceMonitor.measure(.tlsDecrypt) {
            if tlsVersion >= 0x0304 {
                return try decryptTLS13Record(ciphertext: ciphertext, header: header, seqNum: seqNum)
            } else {
                return try decryptTLS12Record(ciphertext: ciphertext, header: header, seqNum: seqNum)
            }
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
