//
//  TLSRecordConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation
import CryptoKit
import CommonCrypto

private let logger = AnywhereLogger(category: "TLS")

// MARK: - TLSRecordConnection

/// TLS application-layer record encryption/decryption wrapper (supports TLS 1.2 and 1.3).
///
/// Encrypts outgoing data into TLS Application Data records and decrypts incoming records.
/// Sequence numbers are tracked independently for client and server directions.
///
/// **TLS 1.3**: Content type is inside the encrypted payload; nonce = IV XOR padded_seq;
/// AAD = record header (5 bytes).
///
/// **TLS 1.2 AEAD (GCM)**: Explicit 8-byte nonce prepended to ciphertext;
/// nonce = implicit_IV(4) || explicit(8); AAD = seq(8) || type(1) || version(2) || length(2).
///
/// **TLS 1.2 AEAD (ChaCha20)**: No explicit nonce; nonce = IV XOR padded_seq;
/// AAD = seq(8) || type(1) || version(2) || length(2).
///
/// **TLS 1.2 CBC**: HMAC-then-encrypt with explicit IV per record.
///
/// Supports a "direct" mode (``receiveRaw(completion:)`` / ``sendRaw(data:completion:)``)
/// that bypasses encryption for Vision direct-copy transitions.
class TLSRecordConnection {

    // MARK: Properties

    /// The underlying transport (``RawTCPSocket`` for direct connections,
    /// ``TunneledTransport`` for proxy-chained connections).
    var connection: (any RawTransport)?

    /// The negotiated TLS version (0x0303 = TLS 1.2, 0x0304 = TLS 1.3).
    let tlsVersion: UInt16

    // TLS encryption keys
    private let clientKey: Data
    private let clientIV: Data
    private let serverKey: Data
    private let serverIV: Data

    // MAC keys for TLS 1.2 CBC cipher suites (empty for AEAD)
    private let clientMACKey: Data
    private let serverMACKey: Data

    // Cipher suite for AEAD dispatch (AES-GCM vs ChaCha20-Poly1305)
    private let cipherSuite: UInt16

    // Cached symmetric keys
    private let clientSymmetricKey: SymmetricKey
    private let serverSymmetricKey: SymmetricKey

    // Sequence numbers
    private var clientSeqNum: UInt64 = 0
    private var serverSeqNum: UInt64 = 0
    private let seqLock = UnfairLock()

    /// Serialises the encrypt-then-enqueue path so that TLS records arrive at
    /// the socket queue in sequence-number order.  Without this, two concurrent
    /// `send` calls can allocate consecutive sequence numbers but enqueue the
    /// encrypted records in reverse order, causing TLS decryption failures on
    /// the server and a "Broken pipe" on the next write.
    private let sendLock = UnfairLock()

    /// Maximum plaintext per record (RFC 8446 §5.1, RFC 5246 §6.2.1).
    private static let maxRecordPlaintext = 16384

    // Receive buffer for batching reads
    private var receiveBuffer = Data(capacity: 256 * 1024)
    private let receiveLock = UnfairLock()

    // MARK: Initialization

    /// Creates a new TLS 1.3 record connection with pre-derived TLS keys.
    ///
    /// - Parameters:
    ///   - clientKey: The client-to-server encryption key.
    ///   - clientIV: The client-to-server initialization vector (12 bytes).
    ///   - serverKey: The server-to-client encryption key.
    ///   - serverIV: The server-to-client initialization vector (12 bytes).
    ///   - cipherSuite: The negotiated TLS 1.3 cipher suite.
    init(clientKey: Data, clientIV: Data, serverKey: Data, serverIV: Data, cipherSuite: UInt16 = TLSCipherSuite.TLS_AES_128_GCM_SHA256) {
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
    }

    /// Creates a new TLS 1.2 record connection with pre-derived keys.
    ///
    /// - Parameters:
    ///   - clientKey: The client-to-server encryption key.
    ///   - clientIV: The client-to-server IV (4 bytes for GCM, 12 for ChaCha20, 16 for CBC).
    ///   - serverKey: The server-to-client encryption key.
    ///   - serverIV: The server-to-client IV.
    ///   - clientMACKey: The client MAC key (empty for AEAD suites).
    ///   - serverMACKey: The server MAC key (empty for AEAD suites).
    ///   - cipherSuite: The negotiated TLS 1.2 cipher suite.
    ///   - protocolVersion: The TLS protocol version (e.g. 0x0303 for TLS 1.2).
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
        initialServerSeqNum: UInt64 = 0
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
    }

    /// Pre-populates the receive buffer with data that was read during the
    /// TLS handshake but belongs to the application layer (e.g. NewSessionTicket).
    /// Must be called before any `receive()` calls.
    func prependToReceiveBuffer(_ data: Data) {
        receiveLock.lock()
        receiveBuffer.append(data)
        receiveLock.unlock()
    }

    // MARK: - Send (Encrypted)

    /// Sends data through the Reality tunnel, encrypting it as a TLS Application Data record.
    ///
    /// - Parameters:
    ///   - data: The plaintext data to encrypt and send.
    ///   - completion: Called with `nil` on success or an error on failure.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        sendLock.lock()
        guard let connection else {
            sendLock.unlock()
            completion(RealityError.connectionFailed("Connection cancelled"))
            return
        }
        do {
            let record = try buildTLSRecords(for: data)
            connection.send(data: record, completion: completion)
            sendLock.unlock()
        } catch {
            sendLock.unlock()
            logger.error("[TLS] Encryption error: \(error.localizedDescription)")
            completion(error)
        }
    }

    /// Sends data through the Reality tunnel without tracking completion.
    ///
    /// - Parameter data: The plaintext data to encrypt and send.
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
            logger.error("[TLS] Encryption error: \(error.localizedDescription)")
        }
    }

    // MARK: - Receive (Encrypted)

    /// Receives and decrypts data from the Reality tunnel.
    ///
    /// Uses buffered reading to process multiple TLS records per network read,
    /// reducing system call overhead.
    ///
    /// - Parameter completion: Called with decrypted data or an error.
    ///   On decryption failure, both raw data and the error are provided
    ///   so the caller (Vision) can switch to direct-copy mode.
    func receive(completion: @escaping (Data?, Error?) -> Void) {
        receiveLock.lock()
        let processed = processBuffer()
        receiveLock.unlock()

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
            case .decryptionFailed(let rawData):
                completion(rawData, RealityError.decryptionFailed)
            }
            return
        }

        fetchMore(completion: completion)
    }

    // MARK: - Send / Receive (Raw, Unencrypted)

    /// Receives raw data without decryption (for Vision direct-copy mode).
    ///
    /// Returns any buffered data first, then reads directly from the socket.
    ///
    /// - Parameter completion: Called with raw data or an error.
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
            completion(nil, RealityError.connectionFailed("Connection cancelled"))
            return
        }
        connection.receive(maximumLength: 65536) { [weak self] data, isComplete, error in
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

    /// Sends raw data without encryption (for Vision direct-copy mode).
    ///
    /// - Parameters:
    ///   - data: The raw data to send.
    ///   - completion: Called with `nil` on success or an error on failure.
    func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        guard let connection else {
            completion(RealityError.connectionFailed("Connection cancelled"))
            return
        }
        connection.send(data: data, completion: completion)
    }

    /// Sends raw data without encryption and without tracking completion.
    ///
    /// - Parameter data: The raw data to send.
    func sendRaw(data: Data) {
        guard let connection else { return }
        connection.send(data: data)
    }

    // MARK: - Cancel

    /// Closes the connection and releases all resources.
    ///
    /// Sends a TLS close_notify alert (best-effort) before closing, matching
    /// Xray-core's `tlsCloseTimeout` behavior. The close_notify is fire-and-forget;
    /// we don't wait for the server's response (Xray-core waits up to 250ms).
    func cancel() {
        sendCloseNotify()

        receiveLock.lock()
        receiveBuffer.removeAll()
        receiveLock.unlock()

        connection?.forceCancel()
        connection = nil
    }

    /// Sends a TLS close_notify alert record (best-effort, fire-and-forget).
    private func sendCloseNotify() {
        sendLock.lock()
        guard let connection else {
            sendLock.unlock()
            return
        }

        do {
            // Alert: level=warning(1), desc=close_notify(0)
            let alertPayload = Data([0x01, 0x00])
            let record: Data
            if tlsVersion >= 0x0304 {
                record = try encryptTLS13Record(plaintext: alertPayload, contentType: 0x15)
            } else {
                record = try encryptTLS12Record(plaintext: alertPayload, contentType: 0x15)
            }
            connection.send(data: record)
            sendLock.unlock()
        } catch {
            sendLock.unlock()
            // Best-effort, ignore errors
        }
    }

    // MARK: - Internal Buffer Processing

    /// Result of processing buffered TLS records.
    private enum BufferResult {
        case data(Data)
        case error(Error)
        case needMore
        case skip
        case decryptionFailed(Data)
    }

    /// Fetches more data from the network and processes it.
    private func fetchMore(completion: @escaping (Data?, Error?) -> Void) {
        guard let connection else {
            completion(nil, RealityError.connectionFailed("Connection cancelled"))
            return
        }
        connection.receive(maximumLength: 65536) { [weak self] data, isComplete, error in
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
            self.receiveLock.unlock()

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
                case .decryptionFailed(let rawData):
                    completion(rawData, RealityError.decryptionFailed)
                }
            } else {
                self.fetchMore(completion: completion)
            }
        }
    }

    /// Processes all complete TLS records in the receive buffer.
    ///
    /// Returns batched decrypted data from multiple records to reduce callback overhead.
    /// Uses an offset to track consumed bytes and compacts once at the end, avoiding
    /// per-record `removeSubrange` calls that create intermediate slices retaining
    /// the entire original backing store.
    /// Must be called while holding `receiveLock`.
    private func processBuffer() -> BufferResult? {
        if receiveBuffer.count == 0 {
            return nil
        }

        var batchedData = Data(capacity: receiveBuffer.count)
        var hasError: Error? = nil
        var recordsProcessed = 0
        var failedRecordData: Data? = nil

        // Track how many bytes from the front have been consumed
        var consumed = 0

        while receiveBuffer.count - consumed >= 5 {
            var contentType: UInt8 = 0
            var recordLen: UInt16 = 0

            receiveBuffer.withUnsafeBytes { ptr in
                let p = ptr.bindMemory(to: UInt8.self)
                contentType = p[consumed]
                recordLen = UInt16(p[consumed + 3]) << 8 | UInt16(p[consumed + 4])
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

            if contentType == 0x17 { // Application Data
                seqLock.lock()
                let seqNum = serverSeqNum
                serverSeqNum += 1
                seqLock.unlock()

                do {
                    let decrypted = try decryptTLSRecord(ciphertext: body, header: header, seqNum: seqNum)
                    consumed += totalLen
                    if !decrypted.isEmpty {
                        batchedData.append(decrypted)
                    }
                } catch {
                    // Reconstruct full record + any trailing data for fallback (rare path)
                    let failed = Data(receiveBuffer[(base + consumed)...])
                    receiveBuffer.removeAll()
                    consumed = 0
                    failedRecordData = failed
                    hasError = error
                    break
                }
            } else if contentType == 0x15 { // Alert
                consumed += totalLen
                hasError = RealityError.connectionFailed("TLS Alert received")
                break
            } else {
                // Other content types (ChangeCipherSpec, etc.) are skipped
                consumed += totalLen
            }
        }

        // Single compaction: remove all consumed bytes at once
        if consumed > 0 {
            if consumed >= receiveBuffer.count {
                receiveBuffer = Data()
            } else {
                receiveBuffer = Data(receiveBuffer.suffix(from: receiveBuffer.startIndex + consumed))
            }
        }

        if let error = hasError {
            if !batchedData.isEmpty {
                if let failedData = failedRecordData {
                    receiveBuffer = failedData
                }
                return .data(batchedData)
            }
            if let rawData = failedRecordData {
                return .decryptionFailed(rawData)
            }
            return .error(error)
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

    /// Encrypts plaintext into one or more TLS Application Data records.
    /// Splits at the maximum (16384 bytes) to prevent record_overflow.
    /// Sequence numbers are reserved atomically so concurrent sends stay ordered.
    private func buildTLSRecords(for data: Data) throws -> Data {
        if data.count <= Self.maxRecordPlaintext {
            return try encryptSingleRecord(plaintext: data, contentType: 0x17)
        }

        let chunkCount = (data.count + Self.maxRecordPlaintext - 1) / Self.maxRecordPlaintext
        var records = Data(capacity: data.count + chunkCount * 64)
        var offset = 0
        while offset < data.count {
            let end = min(offset + Self.maxRecordPlaintext, data.count)
            records.append(try encryptSingleRecord(plaintext: Data(data[offset..<end]), contentType: 0x17))
            offset = end
        }
        return records
    }

    /// Encrypts a single record, dispatching to the appropriate version-specific method.
    private func encryptSingleRecord(plaintext: Data, contentType: UInt8) throws -> Data {
        if tlsVersion >= 0x0304 {
            return try encryptTLS13Record(plaintext: plaintext, contentType: contentType)
        } else {
            return try encryptTLS12Record(plaintext: plaintext, contentType: contentType)
        }
    }

    /// Decrypts a single record, dispatching to the appropriate version-specific method.
    private func decryptTLSRecord(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
        if tlsVersion >= 0x0304 {
            return try decryptTLS13Record(ciphertext: ciphertext, header: header, seqNum: seqNum)
        } else {
            return try decryptTLS12Record(ciphertext: ciphertext, header: header, seqNum: seqNum)
        }
    }

    // MARK: - TLS 1.3 Record Crypto

    /// TLS 1.3 record encryption.
    ///
    /// Inner plaintext = payload || content_type(1).
    /// Nonce = IV XOR padded_seq. AAD = record_header(5).
    /// Record = header(5) || ciphertext || tag(16).
    private func encryptTLS13Record(plaintext: Data, contentType: UInt8 = 0x17) throws -> Data {
        seqLock.lock()
        let seqNum = clientSeqNum
        clientSeqNum += 1
        seqLock.unlock()

        let innerLen = plaintext.count + 1
        let encryptedLen = innerLen + 16

        var nonce = clientIV
        xorSeqIntoNonce(&nonce, seqNum: seqNum)

        var innerPlaintext = Data(count: innerLen)
        innerPlaintext.withUnsafeMutableBytes { buffer in
            plaintext.copyBytes(to: buffer)
            buffer[plaintext.count] = contentType
        }

        let aad = Data([0x17, 0x03, 0x03, UInt8(encryptedLen >> 8), UInt8(encryptedLen & 0xFF)])

        let (sealedCt, sealedTag) = try sealAEAD(plaintext: innerPlaintext, nonce: nonce, aad: aad, key: clientSymmetricKey)

        var record = Data(capacity: 5 + encryptedLen)
        record.append(aad)
        record.append(sealedCt)
        record.append(sealedTag)
        return record
    }

    /// TLS 1.3 record decryption.
    private func decryptTLS13Record(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
        guard ciphertext.count >= 16 else {
            throw RealityError.handshakeFailed("Ciphertext too short")
        }

        var nonce = serverIV
        xorSeqIntoNonce(&nonce, seqNum: seqNum)

        let ct = Data(ciphertext.prefix(ciphertext.count - 16))
        let tag = Data(ciphertext.suffix(16))

        let decrypted = try openAEAD(ciphertext: ct, tag: tag, nonce: nonce, aad: Data(header), key: serverSymmetricKey)

        guard !decrypted.isEmpty else {
            throw RealityError.handshakeFailed("Empty decrypted data")
        }

        // Strip inner content type and padding (RFC 8446 §5.4)
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
            throw RealityError.handshakeFailed("No content type found")
        }

        // Skip handshake records (e.g. NewSessionTicket)
        if innerContentType == 0x16 {
            return Data()
        }

        return decrypted.prefix(Int(contentLen))
    }

    // MARK: - TLS 1.2 Record Crypto

    /// TLS 1.2 record encryption.
    ///
    /// Dispatches between AEAD (GCM/ChaCha20) and CBC+HMAC cipher suites.
    private func encryptTLS12Record(plaintext: Data, contentType: UInt8 = 0x17) throws -> Data {
        seqLock.lock()
        let seqNum = clientSeqNum
        clientSeqNum += 1
        seqLock.unlock()

        let version = tlsVersion

        if TLSCipherSuite.isAEAD(cipherSuite) {
            return try encryptTLS12AEAD(plaintext: plaintext, contentType: contentType, seqNum: seqNum, version: version)
        } else {
            return try encryptTLS12CBC(plaintext: plaintext, contentType: contentType, seqNum: seqNum, version: version)
        }
    }

    /// TLS 1.2 AEAD encryption (AES-GCM or ChaCha20-Poly1305).
    ///
    /// **AES-GCM**: nonce = implicit_IV(4) || explicit_nonce(8); explicit nonce in record.
    /// **ChaCha20**: nonce = IV(12) XOR padded_seq; no explicit nonce in record.
    /// AAD = seq(8) || type(1) || version(2) || plaintext_length(2).
    private func encryptTLS12AEAD(plaintext: Data, contentType: UInt8, seqNum: UInt64, version: UInt16) throws -> Data {
        let isChaCha = TLSCipherSuite.isChaCha20(cipherSuite)
        let explicitNonceLen = isChaCha ? 0 : 8

        // Build nonce
        let nonce: Data
        let explicitNonce: Data
        if isChaCha {
            // ChaCha20: XOR IV with padded seq (same as TLS 1.3)
            var n = clientIV
            xorSeqIntoNonce(&n, seqNum: seqNum)
            nonce = n
            explicitNonce = Data()
        } else {
            // AES-GCM: implicit(4) || explicit(8) where explicit = seq number
            var seqBytes = Data(count: 8)
            for i in 0..<8 { seqBytes[i] = UInt8((seqNum >> ((7 - i) * 8)) & 0xFF) }
            var n = clientIV  // 4 bytes implicit
            n.append(seqBytes)
            nonce = n
            explicitNonce = seqBytes
        }

        // Build AAD: seq(8) || type(1) || version(2) || length(2)
        var aad = Data(capacity: 13)
        for i in 0..<8 { aad.append(UInt8((seqNum >> ((7 - i) * 8)) & 0xFF)) }
        aad.append(contentType)
        aad.append(UInt8(version >> 8))
        aad.append(UInt8(version & 0xFF))
        aad.append(UInt8((plaintext.count >> 8) & 0xFF))
        aad.append(UInt8(plaintext.count & 0xFF))

        let (ct, tag) = try sealAEAD(plaintext: plaintext, nonce: nonce, aad: aad, key: clientSymmetricKey)

        // Record: header(5) || [explicit_nonce(8)] || ciphertext || tag(16)
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

    /// TLS 1.2 CBC+HMAC encryption.
    ///
    /// MAC = HMAC(mac_key, seq || type || version || length || plaintext).
    /// Encrypt: AES-CBC(key, random_IV, plaintext || MAC || padding).
    /// Record: header(5) || IV(16) || encrypted.
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

        // Compute MAC
        let mac = TLS12KeyDerivation.tls10MAC(
            macKey: clientMACKey, seqNum: seqNum,
            contentType: contentType, protocolVersion: version,
            payload: plaintext, useSHA384: useSHA384, useSHA256: useSHA256
        )

        // plaintext || MAC
        var data = plaintext
        data.append(mac)

        // Padding: pad to block size (16 for AES)
        let blockSize = 16
        let paddingLen = blockSize - (data.count % blockSize)
        let paddingByte = UInt8(paddingLen - 1)
        data.append(contentsOf: [UInt8](repeating: paddingByte, count: paddingLen))

        // Generate random IV
        var iv = Data(count: blockSize)
        guard iv.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, blockSize, $0.baseAddress!) }) == errSecSuccess else {
            throw RealityError.handshakeFailed("Failed to generate IV")
        }

        // AES-CBC encrypt (no PKCS7 padding — we handle it ourselves)
        var encrypted = Data(count: data.count)
        var numBytesEncrypted = 0
        let status = encrypted.withUnsafeMutableBytes { outPtr in
            data.withUnsafeBytes { inPtr in
                clientKey.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            0,  // No padding
                            keyPtr.baseAddress!, clientKey.count,
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

        // Record: header(5) || IV(16) || encrypted
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

    /// TLS 1.2 record decryption.
    private func decryptTLS12Record(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
        if TLSCipherSuite.isAEAD(cipherSuite) {
            return try decryptTLS12AEAD(ciphertext: ciphertext, header: header, seqNum: seqNum)
        } else {
            return try decryptTLS12CBC(ciphertext: ciphertext, header: header, seqNum: seqNum)
        }
    }

    /// TLS 1.2 AEAD decryption.
    private func decryptTLS12AEAD(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
        let isChaCha = TLSCipherSuite.isChaCha20(cipherSuite)
        let explicitNonceLen = isChaCha ? 0 : 8
        let version = tlsVersion
        let contentType = header.first ?? 0x17

        guard ciphertext.count >= explicitNonceLen + 16 else {
            throw RealityError.handshakeFailed("Ciphertext too short for TLS 1.2 AEAD")
        }

        // Extract explicit nonce and payload
        let explicitNonce = isChaCha ? Data() : Data(ciphertext.prefix(explicitNonceLen))
        let payload = Data(ciphertext.suffix(from: ciphertext.startIndex + explicitNonceLen))

        // Build nonce
        let nonce: Data
        if isChaCha {
            var n = serverIV
            xorSeqIntoNonce(&n, seqNum: seqNum)
            nonce = n
        } else {
            var n = serverIV  // 4 bytes implicit
            n.append(explicitNonce)
            nonce = n
        }

        // Build AAD: seq(8) || type(1) || version(2) || plaintext_length(2)
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

        return try openAEAD(ciphertext: ct, tag: tag, nonce: nonce, aad: aad, key: serverSymmetricKey)
    }

    /// TLS 1.2 CBC+HMAC decryption.
    private func decryptTLS12CBC(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
        let blockSize = 16
        let version = tlsVersion
        let contentType = header.first ?? 0x17

        guard ciphertext.count >= blockSize * 2 else {
            throw RealityError.handshakeFailed("Ciphertext too short for CBC")
        }

        // Extract IV (first block) and encrypted data
        let iv = Data(ciphertext.prefix(blockSize))
        let encrypted = Data(ciphertext.suffix(from: ciphertext.startIndex + blockSize))

        guard encrypted.count % blockSize == 0 else {
            throw RealityError.handshakeFailed("CBC ciphertext not aligned")
        }

        // AES-CBC decrypt
        var decrypted = Data(count: encrypted.count)
        var numBytesDecrypted = 0
        let status = decrypted.withUnsafeMutableBytes { outPtr in
            encrypted.withUnsafeBytes { inPtr in
                serverKey.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            0,  // No PKCS7 padding
                            keyPtr.baseAddress!, serverKey.count,
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
            throw RealityError.handshakeFailed("CBC decryption failed")
        }

        decrypted = decrypted.prefix(numBytesDecrypted)

        // Validate and strip padding (constant-time to mitigate Lucky13)
        let paddingByte = Int(decrypted.last ?? 0)
        let paddingLen = paddingByte + 1

        // Constant-time padding validation: check all padding bytes without early return
        var paddingGood: UInt8 = 0
        if paddingLen > decrypted.count {
            paddingGood = 1  // Invalid
        } else {
            for i in (decrypted.count - paddingLen)..<decrypted.count {
                paddingGood |= decrypted[i] ^ UInt8(paddingByte)
            }
        }

        guard paddingGood == 0 else {
            throw RealityError.handshakeFailed("Invalid CBC padding")
        }

        decrypted = decrypted.prefix(decrypted.count - paddingLen)

        // Determine MAC size
        let macSize = TLSCipherSuite.macLength(cipherSuite)
        guard decrypted.count >= macSize else {
            throw RealityError.handshakeFailed("Decrypted data too short for MAC")
        }

        // Extract and verify MAC
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
            macKey: serverMACKey, seqNum: seqNum,
            contentType: contentType, protocolVersion: version,
            payload: payload, useSHA384: useSHA384, useSHA256: useSHA256
        )

        // Constant-time comparison to prevent timing attacks
        guard receivedMAC.count == expectedMAC.count,
              constantTimeEqual(receivedMAC, expectedMAC) else {
            throw RealityError.handshakeFailed("MAC verification failed")
        }

        return payload
    }

    /// Constant-time comparison of two Data values to prevent timing side-channel attacks.
    private func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count {
            diff |= a[a.startIndex + i] ^ b[b.startIndex + i]
        }
        return diff == 0
    }

    // MARK: - AEAD Helpers

    /// Seals plaintext with the appropriate AEAD (AES-GCM or ChaCha20-Poly1305).
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

    /// Opens ciphertext with the appropriate AEAD.
    private func openAEAD(ciphertext: Data, tag: Data, nonce: Data, aad: Data, key: SymmetricKey) throws -> Data {
        if TLSCipherSuite.isChaCha20(cipherSuite) {
            let nonceObj = try ChaChaPoly.Nonce(data: nonce)
            let sealedBox = try ChaChaPoly.SealedBox(nonce: nonceObj, ciphertext: ciphertext, tag: tag)
            return Data(try ChaChaPoly.open(sealedBox, using: key, authenticating: aad))
        } else {
            let nonceObj = try AES.GCM.Nonce(data: nonce)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonceObj, ciphertext: ciphertext, tag: tag)
            return Data(try AES.GCM.open(sealedBox, using: key, authenticating: aad))
        }
    }

    /// XORs the 8-byte big-endian sequence number into the last 8 bytes of the nonce.
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
