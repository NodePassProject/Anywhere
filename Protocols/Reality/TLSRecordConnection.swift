//
//  TLSRecordConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation
import CryptoKit
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "Reality")

// MARK: - TLSRecordConnection

/// TLS 1.3 application-layer record encryption/decryption wrapper.
///
/// Encrypts outgoing data into TLS Application Data records using AES-128-GCM (or AES-256-GCM
/// depending on the negotiated cipher suite) and decrypts incoming records. Sequence numbers
/// are tracked independently for client and server directions.
///
/// Supports a "direct" mode (``receiveRaw(completion:)`` / ``sendRaw(data:completion:)``)
/// that bypasses encryption for Vision direct-copy transitions.
class TLSRecordConnection {

    // MARK: Properties

    /// The underlying BSD socket.
    var connection: BSDSocket?

    // TLS encryption keys
    private let clientKey: Data
    private let clientIV: Data
    private let serverKey: Data
    private let serverIV: Data

    // Cached symmetric keys
    private let clientSymmetricKey: SymmetricKey
    private let serverSymmetricKey: SymmetricKey

    // Sequence numbers
    private var clientSeqNum: UInt64 = 0
    private var serverSeqNum: UInt64 = 0
    private let seqLock = UnfairLock()

    // Receive buffer for batching reads
    private var receiveBuffer = Data(capacity: 256 * 1024)
    private let receiveLock = UnfairLock()

    // MARK: Initialization

    /// Creates a new TLS record connection with pre-derived TLS keys.
    ///
    /// - Parameters:
    ///   - clientKey: The client-to-server encryption key.
    ///   - clientIV: The client-to-server initialization vector.
    ///   - serverKey: The server-to-client encryption key.
    ///   - serverIV: The server-to-client initialization vector.
    init(clientKey: Data, clientIV: Data, serverKey: Data, serverIV: Data) {
        self.clientKey = clientKey
        self.clientIV = clientIV
        self.serverKey = serverKey
        self.serverIV = serverIV
        self.clientSymmetricKey = SymmetricKey(data: clientKey)
        self.serverSymmetricKey = SymmetricKey(data: serverKey)
    }

    // MARK: - Send (Encrypted)

    /// Sends data through the Reality tunnel, encrypting it as a TLS Application Data record.
    ///
    /// - Parameters:
    ///   - data: The plaintext data to encrypt and send.
    ///   - completion: Called with `nil` on success or an error on failure.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        guard let connection else {
            completion(RealityError.connectionFailed("Connection cancelled"))
            return
        }
        do {
            seqLock.lock()
            let seqNum = clientSeqNum
            clientSeqNum += 1
            seqLock.unlock()

            let record = try encryptAndBuildTLSRecord(plaintext: data, seqNum: seqNum)
            connection.send(data: record, completion: completion)
        } catch {
            logger.error("[Reality] Encryption error: \(error.localizedDescription, privacy: .public)")
            completion(error)
        }
    }

    /// Sends data through the Reality tunnel without tracking completion.
    ///
    /// - Parameter data: The plaintext data to encrypt and send.
    func send(data: Data) {
        guard let connection else { return }
        do {
            seqLock.lock()
            let seqNum = clientSeqNum
            clientSeqNum += 1
            seqLock.unlock()

            let record = try encryptAndBuildTLSRecord(plaintext: data, seqNum: seqNum)
            connection.send(data: record)
        } catch {
            logger.error("[Reality] Encryption error: \(error.localizedDescription, privacy: .public)")
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
        guard let connection else { return }

        seqLock.lock()
        let seqNum = clientSeqNum
        clientSeqNum += 1
        seqLock.unlock()

        // Alert plaintext: level=warning(1), desc=close_notify(0), inner content type=alert(0x15)
        let alertPlaintext = Data([0x01, 0x00, 0x15])
        let encryptedLen = alertPlaintext.count + 16

        var nonce = clientIV
        nonce.withUnsafeMutableBytes { ptr in
            let p = ptr.bindMemory(to: UInt8.self)
            let base = p.count - 8
            for i in 0..<8 {
                p[base + i] ^= UInt8((seqNum >> ((7 - i) * 8)) & 0xFF)
            }
        }

        do {
            let nonceObj = try AES.GCM.Nonce(data: nonce)
            let aad = Data([0x17, 0x03, 0x03, UInt8(encryptedLen >> 8), UInt8(encryptedLen & 0xFF)])
            let sealedBox = try AES.GCM.seal(alertPlaintext, using: clientSymmetricKey, nonce: nonceObj, authenticating: aad)
            guard let combined = sealedBox.combined else { return }

            var record = Data(capacity: 5 + encryptedLen)
            record.append(contentsOf: [0x17, 0x03, 0x03, UInt8(encryptedLen >> 8), UInt8(encryptedLen & 0xFF)])
            record.append(combined.suffix(from: 12))
            connection.send(data: record)
        } catch {
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
    /// Must be called while holding `receiveLock`.
    private func processBuffer() -> BufferResult? {
        if receiveBuffer.count == 0 {
            return nil
        }

        var batchedData = Data(capacity: receiveBuffer.count)
        var hasError: Error? = nil
        var recordsProcessed = 0
        var failedRecordData: Data? = nil

        while receiveBuffer.count >= 5 {
            var contentType: UInt8 = 0
            var recordLen: UInt16 = 0

            let hasHeader = receiveBuffer.withUnsafeBytes { ptr -> Bool in
                guard ptr.count >= 5 else { return false }
                let p = ptr.bindMemory(to: UInt8.self)
                contentType = p[0]
                recordLen = UInt16(p[3]) << 8 | UInt16(p[4])
                return true
            }

            guard hasHeader else { break }

            let totalLen = 5 + Int(recordLen)
            guard receiveBuffer.count >= totalLen else { break }

            let headerStart = receiveBuffer.startIndex
            let headerEnd = headerStart + 5
            let bodyEnd = headerStart + totalLen

            let header = Data(receiveBuffer[headerStart..<headerEnd])
            let body = Data(receiveBuffer[headerEnd..<bodyEnd])
            let fullRecord = Data(receiveBuffer[headerStart..<bodyEnd])

            receiveBuffer.removeSubrange(headerStart..<bodyEnd)
            recordsProcessed += 1

            // Compact buffer to reclaim backing storage
            if receiveBuffer.isEmpty {
                receiveBuffer = Data()
            }

            if contentType == 0x17 { // Application Data
                seqLock.lock()
                let seqNum = serverSeqNum
                serverSeqNum += 1
                seqLock.unlock()

                do {
                    let decrypted = try decryptTLSRecord(ciphertext: body, header: header, seqNum: seqNum)
                    if !decrypted.isEmpty {
                        batchedData.append(decrypted)
                    }
                } catch {
                    failedRecordData = fullRecord
                    if !receiveBuffer.isEmpty {
                        failedRecordData!.append(receiveBuffer)
                        receiveBuffer.removeAll()
                    }
                    hasError = error
                    break
                }
            } else if contentType == 0x15 { // Alert
                hasError = RealityError.connectionFailed("TLS Alert received")
                break
            }
            // Other content types (ChangeCipherSpec, etc.) are skipped
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

    // MARK: - TLS Record Crypto

    private func decryptTLSRecord(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
        guard ciphertext.count >= 16 else {
            throw RealityError.handshakeFailed("Ciphertext too short")
        }

        var nonce = serverIV
        nonce.withUnsafeMutableBytes { ptr in
            let p = ptr.bindMemory(to: UInt8.self)
            let base = p.count - 8
            for i in 0..<8 {
                p[base + i] ^= UInt8((seqNum >> ((7 - i) * 8)) & 0xFF)
            }
        }
        let nonceObj = try AES.GCM.Nonce(data: nonce)

        let tagOffset = ciphertext.count - 16
        let ct = ciphertext.prefix(tagOffset)
        let tag = ciphertext.suffix(16)

        let sealedBox = try AES.GCM.SealedBox(nonce: nonceObj, ciphertext: ct, tag: tag)
        let decrypted = try AES.GCM.open(sealedBox, using: serverSymmetricKey, authenticating: header)

        guard !decrypted.isEmpty else {
            throw RealityError.handshakeFailed("Empty decrypted data")
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
            throw RealityError.handshakeFailed("No content type found")
        }

        if innerContentType == 0x16 {
            return Data()
        }

        return decrypted.prefix(Int(contentLen))
    }

    private func encryptAndBuildTLSRecord(plaintext: Data, seqNum: UInt64) throws -> Data {
        let innerLen = plaintext.count + 1
        let encryptedLen = innerLen + 16

        var nonce = clientIV
        nonce.withUnsafeMutableBytes { ptr in
            let p = ptr.bindMemory(to: UInt8.self)
            let base = p.count - 8
            for i in 0..<8 {
                p[base + i] ^= UInt8((seqNum >> ((7 - i) * 8)) & 0xFF)
            }
        }

        var innerPlaintext = Data(count: innerLen)
        innerPlaintext.withUnsafeMutableBytes { buffer in
            plaintext.copyBytes(to: buffer)
            buffer[plaintext.count] = 0x17
        }

        let aad = Data([0x17, 0x03, 0x03, UInt8(encryptedLen >> 8), UInt8(encryptedLen & 0xFF)])

        let nonceObj = try AES.GCM.Nonce(data: nonce)
        let sealedBox = try AES.GCM.seal(innerPlaintext, using: clientSymmetricKey, nonce: nonceObj, authenticating: aad)

        guard let combined = sealedBox.combined else {
            throw RealityError.handshakeFailed("Failed to get combined sealed box")
        }

        var record = Data(count: 5 + encryptedLen)
        record.withUnsafeMutableBytes { buffer in
            let ptr = buffer.bindMemory(to: UInt8.self)
            buffer[0] = 0x17
            buffer[1] = 0x03
            buffer[2] = 0x03
            buffer[3] = UInt8(encryptedLen >> 8)
            buffer[4] = UInt8(encryptedLen & 0xFF)
            combined.withUnsafeBytes { srcBuffer in
                let src = srcBuffer.bindMemory(to: UInt8.self)
                for i in 12..<combined.count {
                    ptr[5 + i - 12] = src[i]
                }
            }
        }

        return record
    }
}
