//
//  TLSRecordConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation
import CryptoKit
import CommonCrypto

private let logger = AnywhereLogger(category: "TLSRecordConnection")

// MARK: - TLSRecordConnection

nonisolated class TLSRecordConnection {

    // MARK: Properties

    var connection: (any RawTransport)?

    /// The negotiated TLS version.
    let tlsVersion: UInt16

    /// The value of the ALPN sent by the peer; empty when the peer selected none.
    var negotiatedALPN: String = ""

    // Mutable so a TLS 1.3 post-handshake KeyUpdate (RFC 8446 §7.2) can install the next
    // key generation. Egress (`*Key`/`*IV` for our send direction) is only mutated under
    // `sendLock`; ingress (our read direction) only from the receive path. See `rekeyIngress`.
    private var clientKey: Data
    private var clientIV: Data
    private var serverKey: Data
    private var serverIV: Data

    private let clientMACKey: Data
    private let serverMACKey: Data

    private let cipherSuite: UInt16

    private var clientSymmetricKey: SymmetricKey
    private var serverSymmetricKey: SymmetricKey

    /// TLS 1.3 application traffic secrets, retained so KeyUpdate can derive the next
    /// generation. `nil` for TLS 1.2 (which has no KeyUpdate) and disables KeyUpdate handling.
    private var clientAppSecret: Data?
    private var serverAppSecret: Data?

    /// Set on the receive path when a peer KeyUpdate(update_requested) arrives; consumed after
    /// `receiveLock` is released so we can send our own KeyUpdate without holding it.
    private var keyUpdateResponsePending = false

    private var clientSeqNum: UInt64 = 0
    private var serverSeqNum: UInt64 = 0
    private let seqLock = UnfairLock()

    private let sendLock = UnfairLock()

    private static let maxRecordPlaintext = 16384

    private var receiveBuffer = Data(capacity: 256 * 1024)
    private let receiveLock = UnfairLock()
    
    private var receivedCloseNotify = false

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

    private var egressKey: Data { direction == .server ? serverKey : clientKey }
    private var egressIV: Data { direction == .server ? serverIV : clientIV }
    private var egressSymmetricKey: SymmetricKey {
        direction == .server ? serverSymmetricKey : clientSymmetricKey
    }
    private var egressMACKey: Data { direction == .server ? serverMACKey : clientMACKey }

    private var ingressKey: Data { direction == .server ? clientKey : serverKey }
    private var ingressIV: Data { direction == .server ? clientIV : serverIV }
    private var ingressSymmetricKey: SymmetricKey {
        direction == .server ? clientSymmetricKey : serverSymmetricKey
    }
    private var ingressMACKey: Data { direction == .server ? clientMACKey : serverMACKey }

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

            receiveBuffer.withUnsafeBytes { ptr in
                let p = ptr.bindMemory(to: UInt8.self)
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

    // MARK: - TLS 1.3 Record Crypto

    private func encryptTLS13Record(plaintext: Data, contentType: UInt8 = TLSContentType.applicationData) throws -> Data {
        seqLock.lock()
        let seqNum: UInt64
        if direction == .server {
            seqNum = serverSeqNum
            serverSeqNum += 1
        } else {
            seqNum = clientSeqNum
            clientSeqNum += 1
        }
        seqLock.unlock()

        let innerLen = plaintext.count + 1
        let encryptedLen = innerLen + 16

        var nonce = egressIV
        xorSeqIntoNonce(&nonce, seqNum: seqNum)

        var innerPlaintext = Data(count: innerLen)
        innerPlaintext.withUnsafeMutableBytes { buffer in
            plaintext.copyBytes(to: buffer)
            buffer[plaintext.count] = contentType
        }

        let aad = Data([TLSContentType.applicationData, 0x03, 0x03, UInt8(encryptedLen >> 8), UInt8(encryptedLen & 0xFF)])

        let (sealedCt, sealedTag) = try sealAEAD(plaintext: innerPlaintext, nonce: nonce, aad: aad, key: egressSymmetricKey)

        var record = Data(capacity: 5 + encryptedLen)
        record.append(aad)
        record.append(sealedCt)
        record.append(sealedTag)
        return record
    }

    private func decryptTLS13Record(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
        guard ciphertext.count >= 16 else {
            throw TLSRecordError.ciphertextTooShort
        }

        var nonce = ingressIV
        xorSeqIntoNonce(&nonce, seqNum: seqNum)

        let ct = ciphertext.prefix(ciphertext.count - 16)
        let tag = ciphertext.suffix(16)

        let decrypted = try openAEAD(ciphertext: ct, tag: tag, nonce: nonce, aad: header, key: ingressSymmetricKey)

        guard !decrypted.isEmpty else {
            throw TLSRecordError.emptyDecryptedData
        }

        var innerContentType: UInt8 = 0
        let contentLen: ssize_t = decrypted.withUnsafeBytes { ptr -> ssize_t in
            let p = ptr.bindMemory(to: UInt8.self)
            var i = p.count - 1
            while i >= 0 && p[i] == 0 { i -= 1 }
            guard i >= 0 else { return -1 }
            innerContentType = p[i]
            return ssize_t(i)
        }

        guard contentLen >= 0 else {
            throw TLSRecordError.noContentTypeFound
        }

        // Post-handshake handshake messages (NewSessionTicket, KeyUpdate). They carry no
        // application data, but a KeyUpdate must rekey the read side here or every subsequent
        // record fails AEAD authentication (RFC 8446 §7.2).
        if innerContentType == TLSContentType.handshake {
            handlePostHandshakeTLS13(Data(decrypted.prefix(Int(contentLen))))
            return Data()
        }

        if innerContentType == TLSContentType.alert {
            let body = decrypted.prefix(Int(contentLen))
            let level = body.first ?? 0
            let description = body.count >= 2 ? body[body.startIndex + 1] : 0
            if description == TLSAlertDescription.closeNotify {
                receivedCloseNotify = true
                return Data()
            }
            throw TLSRecordError.tlsAlert(level: level, description: description)
        }

        return decrypted.prefix(Int(contentLen))
    }

    // MARK: - TLS 1.3 KeyUpdate (RFC 8446 §7.2)

    /// Parse post-handshake handshake messages from a decrypted TLS 1.3 record and act on any
    /// KeyUpdate. Runs on the receive path with `receiveLock` held (and never `seqLock`).
    private func handlePostHandshakeTLS13(_ messages: Data) {
        var i = messages.startIndex
        let end = messages.endIndex
        while i + 4 <= end {
            let type = messages[i]
            let len = Int(messages[i + 1]) << 16 | Int(messages[i + 2]) << 8 | Int(messages[i + 3])
            let bodyStart = i + 4
            let bodyEnd = bodyStart + len
            guard bodyEnd <= end else { break }

            if type == TLSHandshakeType.keyUpdate {
                // The peer has switched its sending keys, so advance ours for reading now.
                rekeyIngress()
                // request_update == 1 ("update_requested") obliges us to KeyUpdate back.
                let requestUpdate = len >= 1 ? messages[bodyStart] : 0
                if requestUpdate == 1 {
                    keyUpdateResponsePending = true
                }
            }
            // NewSessionTicket and any other post-handshake messages need no record-layer
            // change and are intentionally ignored.
            i = bodyEnd
        }
    }

    /// Advance the *read* (ingress) traffic secret, key and IV, and reset the read sequence
    /// number, after the peer sent a KeyUpdate. Ingress is the server keys for a client and the
    /// client keys for a server. No-op when the traffic secret is unavailable (e.g. TLS 1.2).
    private func rekeyIngress() {
        let kd = TLS13KeyDerivation(cipherSuite: cipherSuite)
        if direction == .server {
            guard let current = clientAppSecret else { return }
            let next = kd.nextApplicationGeneration(trafficSecret: current)
            seqLock.lock()
            clientAppSecret = next.secret
            clientKey = next.key
            clientIV = next.iv
            clientSymmetricKey = SymmetricKey(data: next.key)
            clientSeqNum = 0
            seqLock.unlock()
        } else {
            guard let current = serverAppSecret else { return }
            let next = kd.nextApplicationGeneration(trafficSecret: current)
            seqLock.lock()
            serverAppSecret = next.secret
            serverKey = next.key
            serverIV = next.iv
            serverSymmetricKey = SymmetricKey(data: next.key)
            serverSeqNum = 0
            seqLock.unlock()
        }
    }

    /// Reply to a KeyUpdate(update_requested): send our own KeyUpdate(update_not_requested) using
    /// the *current* write keys, then advance the write (egress) traffic secret, key and IV and
    /// reset the write sequence number. Held under `sendLock` so the key switch is atomic with
    /// respect to application sends; called only after `receiveLock` has been released.
    private func sendKeyUpdateResponseAndRekeyEgress() {
        sendLock.lock()
        defer { sendLock.unlock() }

        guard let connection else { return }

        // KeyUpdate message: msg_type(24) | uint24 length(1) | request_update == update_not_requested(0).
        let keyUpdate = Data([TLSHandshakeType.keyUpdate, 0x00, 0x00, 0x01, 0x00])
        do {
            let record = try encryptTLS13Record(plaintext: keyUpdate, contentType: TLSContentType.handshake)
            connection.send(data: record)
        } catch {
            return
        }

        let kd = TLS13KeyDerivation(cipherSuite: cipherSuite)
        if direction == .server {
            guard let current = serverAppSecret else { return }
            let next = kd.nextApplicationGeneration(trafficSecret: current)
            seqLock.lock()
            serverAppSecret = next.secret
            serverKey = next.key
            serverIV = next.iv
            serverSymmetricKey = SymmetricKey(data: next.key)
            serverSeqNum = 0
            seqLock.unlock()
        } else {
            guard let current = clientAppSecret else { return }
            let next = kd.nextApplicationGeneration(trafficSecret: current)
            seqLock.lock()
            clientAppSecret = next.secret
            clientKey = next.key
            clientIV = next.iv
            clientSymmetricKey = SymmetricKey(data: next.key)
            clientSeqNum = 0
            seqLock.unlock()
        }
    }

    // MARK: - TLS 1.2 Record Crypto

    private func encryptTLS12Record(plaintext: Data, contentType: UInt8 = TLSContentType.applicationData) throws -> Data {
        seqLock.lock()
        let seqNum: UInt64
        if direction == .server {
            seqNum = serverSeqNum
            serverSeqNum += 1
        } else {
            seqNum = clientSeqNum
            clientSeqNum += 1
        }
        seqLock.unlock()

        let version = tlsVersion

        if TLSCipherSuite.isAEAD(cipherSuite) {
            return try encryptTLS12AEAD(plaintext: plaintext, contentType: contentType, seqNum: seqNum, version: version)
        } else {
            return try encryptTLS12CBC(plaintext: plaintext, contentType: contentType, seqNum: seqNum, version: version)
        }
    }

    private func encryptTLS12AEAD(plaintext: Data, contentType: UInt8, seqNum: UInt64, version: UInt16) throws -> Data {
        let isChaCha = TLSCipherSuite.isChaCha20(cipherSuite)
        let explicitNonceLen = isChaCha ? 0 : 8

        let nonce: Data
        let explicitNonce: Data
        if isChaCha {
            var n = egressIV
            xorSeqIntoNonce(&n, seqNum: seqNum)
            nonce = n
            explicitNonce = Data()
        } else {
            var seqBytes = Data(count: 8)
            for i in 0..<8 { seqBytes[i] = UInt8((seqNum >> ((7 - i) * 8)) & 0xFF) }
            var n = egressIV
            n.append(seqBytes)
            nonce = n
            explicitNonce = seqBytes
        }

        var aad = Data(capacity: 13)
        for i in 0..<8 { aad.append(UInt8((seqNum >> ((7 - i) * 8)) & 0xFF)) }
        aad.append(contentType)
        aad.append(UInt8(version >> 8))
        aad.append(UInt8(version & 0xFF))
        aad.append(UInt8((plaintext.count >> 8) & 0xFF))
        aad.append(UInt8(plaintext.count & 0xFF))

        let (ct, tag) = try sealAEAD(plaintext: plaintext, nonce: nonce, aad: aad, key: egressSymmetricKey)

        let recordPayloadLen = explicitNonceLen + ct.count + tag.count
        var record = Data(capacity: 5 + recordPayloadLen)
        record.append(contentType)
        record.append(UInt8(version >> 8))
        record.append(UInt8(version & 0xFF))
        record.append(UInt8((recordPayloadLen >> 8) & 0xFF))
        record.append(UInt8(recordPayloadLen & 0xFF))
        record.append(explicitNonce)
        record.append(ct)
        record.append(tag)
        return record
    }

    private func encryptTLS12CBC(plaintext: Data, contentType: UInt8, seqNum: UInt64, version: UInt16) throws -> Data {
        let useSHA384 = TLSCipherSuite.usesSHA384(cipherSuite)
        let useSHA256: Bool
        switch cipherSuite {
        case TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
             TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
             TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
             TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
            useSHA256 = true
        default:
            useSHA256 = false
        }

        let mac = TLS12KeyDerivation.tls10MAC(
            macKey: egressMACKey, seqNum: seqNum,
            contentType: contentType, protocolVersion: version,
            payload: plaintext, useSHA384: useSHA384, useSHA256: useSHA256
        )

        var data = plaintext
        data.append(mac)

        let blockSize = 16
        let paddingLen = blockSize - (data.count % blockSize)
        let paddingByte = UInt8(paddingLen - 1)
        data.append(contentsOf: [UInt8](repeating: paddingByte, count: paddingLen))

        var iv = Data(count: blockSize)
        guard iv.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, blockSize, $0.baseAddress!) }) == errSecSuccess else {
            throw TLSRecordError.ivGenerationFailed
        }

        var encrypted = Data(count: data.count)
        var numBytesEncrypted = 0
        let cbcKey = egressKey
        let status = encrypted.withUnsafeMutableBytes { outPtr in
            data.withUnsafeBytes { inPtr in
                cbcKey.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            0,
                            keyPtr.baseAddress!, cbcKey.count,
                            ivPtr.baseAddress!,
                            inPtr.baseAddress!, data.count,
                            outPtr.baseAddress!, data.count,
                            &numBytesEncrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw TLSRecordError.encryptionFailed
        }

        let recordPayloadLen = blockSize + numBytesEncrypted
        var record = Data(capacity: 5 + recordPayloadLen)
        record.append(contentType)
        record.append(UInt8(version >> 8))
        record.append(UInt8(version & 0xFF))
        record.append(UInt8((recordPayloadLen >> 8) & 0xFF))
        record.append(UInt8(recordPayloadLen & 0xFF))
        record.append(iv)
        record.append(encrypted.prefix(numBytesEncrypted))
        return record
    }

    private func decryptTLS12Record(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
        if TLSCipherSuite.isAEAD(cipherSuite) {
            return try decryptTLS12AEAD(ciphertext: ciphertext, header: header, seqNum: seqNum)
        } else {
            return try decryptTLS12CBC(ciphertext: ciphertext, header: header, seqNum: seqNum)
        }
    }

    private func decryptTLS12AEAD(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
        let isChaCha = TLSCipherSuite.isChaCha20(cipherSuite)
        let explicitNonceLen = isChaCha ? 0 : 8
        let version = tlsVersion
        let contentType = header.first ?? TLSContentType.applicationData

        guard ciphertext.count >= explicitNonceLen + 16 else {
            throw TLSRecordError.ciphertextTooShort
        }

        let explicitNonce = isChaCha ? Data() : Data(ciphertext.prefix(explicitNonceLen))
        let payload = Data(ciphertext.suffix(from: ciphertext.startIndex + explicitNonceLen))

        let nonce: Data
        if isChaCha {
            var n = ingressIV
            xorSeqIntoNonce(&n, seqNum: seqNum)
            nonce = n
        } else {
            var n = ingressIV
            n.append(explicitNonce)
            nonce = n
        }

        let plaintextLen = payload.count - 16
        var aad = Data(capacity: 13)
        for i in 0..<8 { aad.append(UInt8((seqNum >> ((7 - i) * 8)) & 0xFF)) }
        aad.append(contentType)
        aad.append(UInt8(version >> 8))
        aad.append(UInt8(version & 0xFF))
        aad.append(UInt8((plaintextLen >> 8) & 0xFF))
        aad.append(UInt8(plaintextLen & 0xFF))

        let ct = Data(payload.prefix(payload.count - 16))
        let tag = Data(payload.suffix(16))

        return try openAEAD(ciphertext: ct, tag: tag, nonce: nonce, aad: aad, key: ingressSymmetricKey)
    }

    private func decryptTLS12CBC(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
        let blockSize = 16
        let version = tlsVersion
        let contentType = header.first ?? TLSContentType.applicationData

        guard ciphertext.count >= blockSize * 2 else {
            throw TLSRecordError.ciphertextTooShort
        }

        let iv = Data(ciphertext.prefix(blockSize))
        let encrypted = Data(ciphertext.suffix(from: ciphertext.startIndex + blockSize))

        guard encrypted.count % blockSize == 0 else {
            throw TLSRecordError.malformedRecord("CBC ciphertext not block-aligned")
        }

        var decrypted = Data(count: encrypted.count)
        var numBytesDecrypted = 0
        let cbcKey = ingressKey
        let status = decrypted.withUnsafeMutableBytes { outPtr in
            encrypted.withUnsafeBytes { inPtr in
                cbcKey.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            0,
                            keyPtr.baseAddress!, cbcKey.count,
                            ivPtr.baseAddress!,
                            inPtr.baseAddress!, encrypted.count,
                            outPtr.baseAddress!, encrypted.count,
                            &numBytesDecrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess, numBytesDecrypted > 0 else {
            throw TLSRecordError.malformedRecord("CBC decryption failed")
        }

        decrypted = decrypted.prefix(numBytesDecrypted)

        let paddingByte = Int(decrypted.last ?? 0)
        let paddingLen = paddingByte + 1

        var paddingGood: UInt8 = 0
        if paddingLen > decrypted.count {
            paddingGood = 1
        } else {
            for i in (decrypted.count - paddingLen)..<decrypted.count {
                paddingGood |= decrypted[i] ^ UInt8(paddingByte)
            }
        }

        guard paddingGood == 0 else {
            throw TLSRecordError.invalidPadding
        }

        decrypted = decrypted.prefix(decrypted.count - paddingLen)

        let macSize = TLSCipherSuite.macLength(cipherSuite)
        guard decrypted.count >= macSize else {
            throw TLSRecordError.malformedRecord("decrypted record too short for MAC")
        }

        let payload = Data(decrypted.prefix(decrypted.count - macSize))
        let receivedMAC = Data(decrypted.suffix(macSize))

        let useSHA384 = TLSCipherSuite.usesSHA384(cipherSuite)
        let useSHA256: Bool
        switch cipherSuite {
        case TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
             TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
             TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
             TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
            useSHA256 = true
        default:
            useSHA256 = false
        }

        let expectedMAC = TLS12KeyDerivation.tls10MAC(
            macKey: ingressMACKey, seqNum: seqNum,
            contentType: contentType, protocolVersion: version,
            payload: payload, useSHA384: useSHA384, useSHA256: useSHA256
        )

        guard receivedMAC.count == expectedMAC.count,
              constantTimeEqual(receivedMAC, expectedMAC) else {
            throw TLSRecordError.macVerificationFailed
        }

        return payload
    }

    private func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count {
            diff |= a[a.startIndex + i] ^ b[b.startIndex + i]
        }
        return diff == 0
    }

    // MARK: - AEAD Helpers

    private func sealAEAD(plaintext: Data, nonce: Data, aad: Data, key: SymmetricKey) throws -> (ciphertext: Data, tag: Data) {
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

    private func openAEAD(ciphertext: Data, tag: Data, nonce: Data, aad: Data, key: SymmetricKey) throws -> Data {
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
    private func xorSeqIntoNonce(_ nonce: inout Data, seqNum: UInt64) {
        nonce.withUnsafeMutableBytes { ptr in
            let p = ptr.bindMemory(to: UInt8.self)
            let base = p.count - 8
            for i in 0..<8 {
                p[base + i] ^= UInt8((seqNum >> ((7 - i) * 8)) & 0xFF)
            }
        }
    }
}
