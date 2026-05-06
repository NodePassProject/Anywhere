//
//  VMessConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/6/26.
//

import Foundation

final class VMessConnection: ProxyConnection {
    private let inner: ProxyConnection
    private let session: VMessSession

    private let stateLock = UnfairLock()
    private var responseHeaderReceived = false
    private var receiveBuffer = Data()
    private var receiveBufferOffset = 0
    private var requestChunkCounter: UInt16 = 0
    private var responseChunkCounter: UInt16 = 0
    private var requestSizeParser: VMessCrypto.ShakeSizeParser?
    private var responseSizeParser: VMessCrypto.ShakeSizeParser?

    init(inner: ProxyConnection, session: VMessSession) {
        self.inner = inner
        self.session = session
        if session.usesChunkMasking {
            self.requestSizeParser = VMessCrypto.ShakeSizeParser(nonce: session.requestBodyIV)
            self.responseSizeParser = VMessCrypto.ShakeSizeParser(nonce: session.responseBodyIV)
        }
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }

    func sendHandshake(
        requestHeader: Data,
        initialData: Data?,
        completion: @escaping (Error?) -> Void
    ) {
        do {
            var payload = requestHeader
            if let initialData, !initialData.isEmpty {
                payload.append(try encodeBody(initialData))
            }
            inner.sendRaw(data: payload, completion: completion)
        } catch {
            completion(error)
        }
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        do {
            let payload = try encodeBody(data)
            guard !payload.isEmpty else {
                completion(nil)
                return
            }
            inner.sendRaw(data: payload, completion: completion)
        } catch {
            completion(error)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { _ in }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        readResponseHeaderIfNeeded { [weak self] error in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Connection deallocated"))
                return
            }
            if let error {
                completion(nil, error)
                return
            }

            if !self.session.usesChunkStream {
                if let buffered = self.takeBufferedRemainder(), !buffered.isEmpty {
                    completion(buffered, nil)
                    return
                }
                self.inner.receiveRaw(completion: completion)
                return
            }

            self.readNextChunk(completion: completion)
        }
    }

    override func cancel() {
        stateLock.lock()
        receiveBuffer.removeAll(keepingCapacity: false)
        receiveBufferOffset = 0
        stateLock.unlock()
        inner.cancel()
    }

    override func receiveDirectRaw(completion: @escaping (Data?, Error?) -> Void) {
        inner.receiveDirectRaw(completion: completion)
    }

    override func sendDirectRaw(data: Data, completion: @escaping (Error?) -> Void) {
        inner.sendDirectRaw(data: data, completion: completion)
    }

    override func sendDirectRaw(data: Data) {
        inner.sendDirectRaw(data: data)
    }

    // MARK: - Body Encoding

    private func encodeBody(_ data: Data) throws -> Data {
        guard session.usesChunkStream else { return data }
        guard !data.isEmpty else { return Data() }

        let overhead = session.security.aeadTagSize
        let maxPadding = session.usesGlobalPadding ? 63 : 0
        let maxPayload = max(1, min(16 * 1024, Int(UInt16.max) - overhead - maxPadding))
        let shouldSplit = session.command != .udp
        var offset = 0
        var output = Data(capacity: data.count + ((data.count / maxPayload) + 1) * (2 + overhead + maxPadding))

        repeat {
            let remaining = data.count - offset
            let count = shouldSplit ? min(remaining, maxPayload) : remaining
            guard count + overhead + maxPadding <= Int(UInt16.max) else {
                throw ProxyError.protocolError("VMess UDP payload is too large")
            }

            let chunk = Data(data[offset..<offset + count])
            let sealed = try sealChunk(chunk)
            let chunkSize = prepareRequestChunkSize(payloadSize: UInt16(sealed.count))
            VMessCrypto.appendUInt16BE(chunkSize.encodedSize, to: &output)
            output.append(sealed)
            if chunkSize.paddingLength > 0 {
                output.append(VMessCrypto.randomData(count: Int(chunkSize.paddingLength)))
            }
            offset += count
        } while offset < data.count

        return output
    }

    private func sealChunk(_ plaintext: Data) throws -> Data {
        switch session.security {
        case .aes128GCM:
            return try VMessCrypto.sealAESGCM(
                key: session.requestBodyKey,
                nonce: nextRequestNonce(),
                plaintext: plaintext
            )
        case .chacha20Poly1305:
            return try VMessCrypto.sealChaCha20Poly1305(
                key: session.requestBodyKey,
                nonce: nextRequestNonce(),
                plaintext: plaintext,
                expandedKey: session.requestChaCha20Poly1305Key
            )
        case .auto:
            return try VMessCrypto.sealAESGCM(
                key: session.requestBodyKey,
                nonce: nextRequestNonce(),
                plaintext: plaintext
            )
        case .none, .zero:
            return plaintext
        }
    }

    private func openChunk(_ ciphertext: Data) throws -> Data {
        switch session.security {
        case .aes128GCM:
            return try VMessCrypto.openAESGCM(
                key: session.responseBodyKey,
                nonce: nextResponseNonce(),
                ciphertextAndTag: ciphertext
            )
        case .chacha20Poly1305:
            return try VMessCrypto.openChaCha20Poly1305(
                key: session.responseBodyKey,
                nonce: nextResponseNonce(),
                ciphertextAndTag: ciphertext,
                expandedKey: session.responseChaCha20Poly1305Key
            )
        case .auto:
            return try VMessCrypto.openAESGCM(
                key: session.responseBodyKey,
                nonce: nextResponseNonce(),
                ciphertextAndTag: ciphertext
            )
        case .none, .zero:
            return ciphertext
        }
    }

    private func nextRequestNonce() -> Data {
        stateLock.lock()
        let nonce = VMessConnection.chunkNonce(base: session.requestBodyIV, counter: requestChunkCounter)
        requestChunkCounter &+= 1
        stateLock.unlock()
        return nonce
    }

    private func nextResponseNonce() -> Data {
        stateLock.lock()
        let nonce = VMessConnection.chunkNonce(base: session.responseBodyIV, counter: responseChunkCounter)
        responseChunkCounter &+= 1
        stateLock.unlock()
        return nonce
    }

    private static func chunkNonce(base: Data, counter: UInt16) -> Data {
        var nonce = base
        nonce[0] = UInt8(counter >> 8)
        nonce[1] = UInt8(counter & 0xff)
        return Data(nonce.prefix(12))
    }

    private func prepareRequestChunkSize(payloadSize: UInt16) -> (encodedSize: UInt16, paddingLength: UInt16) {
        stateLock.lock()
        let padding = session.usesGlobalPadding ? (requestSizeParser?.nextPaddingLength() ?? 0) : 0
        let size = payloadSize + padding
        let encoded = session.usesChunkMasking ? (requestSizeParser?.encode(size) ?? size) : size
        stateLock.unlock()
        return (encoded, padding)
    }

    private func decodeResponseChunkSize(_ encoded: UInt16) -> (size: UInt16, padding: UInt16) {
        stateLock.lock()
        let padding = session.usesGlobalPadding ? (responseSizeParser?.nextPaddingLength() ?? 0) : 0
        let size = session.usesChunkMasking ? (responseSizeParser?.decode(encoded) ?? encoded) : encoded
        stateLock.unlock()
        return (size, padding)
    }

    // MARK: - Response Decoding

    private func readResponseHeaderIfNeeded(completion: @escaping (Error?) -> Void) {
        stateLock.lock()
        if responseHeaderReceived {
            stateLock.unlock()
            completion(nil)
            return
        }
        stateLock.unlock()

        ensureBytes(18) { [weak self] error in
            guard let self else {
                completion(ProxyError.connectionFailed("Connection deallocated"))
                return
            }
            if let error {
                completion(error)
                return
            }

            let encryptedLength = self.takeBytes(18)
            do {
                let lengthPlaintext = try VMessCrypto.openAESGCM(
                    key: self.session.responseHeaderLengthKey,
                    nonce: self.session.responseHeaderLengthIV,
                    ciphertextAndTag: encryptedLength
                )
                guard lengthPlaintext.count == 2 else {
                    completion(ProxyError.invalidResponse("Invalid VMess response header length"))
                    return
                }
                let payloadLength = Int(VMessCrypto.readUInt16BE(lengthPlaintext))
                self.readResponseHeaderPayload(length: payloadLength, completion: completion)
            } catch {
                completion(error)
            }
        }
    }

    private func readResponseHeaderPayload(length: Int, completion: @escaping (Error?) -> Void) {
        ensureBytes(length + 16) { [weak self] error in
            guard let self else {
                completion(ProxyError.connectionFailed("Connection deallocated"))
                return
            }
            if let error {
                completion(error)
                return
            }

            let encryptedPayload = self.takeBytes(length + 16)
            do {
                let payload = try VMessCrypto.openAESGCM(
                    key: self.session.responseHeaderPayloadKey,
                    nonce: self.session.responseHeaderPayloadIV,
                    ciphertextAndTag: encryptedPayload
                )
                guard payload.count >= 4 else {
                    completion(ProxyError.invalidResponse("VMess response header is too short"))
                    return
                }
                guard payload[payload.startIndex] == self.session.responseHeader else {
                    completion(ProxyError.invalidResponse("Unexpected VMess response header"))
                    return
                }

                self.stateLock.lock()
                self.responseHeaderReceived = true
                self.stateLock.unlock()
                completion(nil)
            } catch {
                completion(error)
            }
        }
    }

    private func readNextChunk(completion: @escaping (Data?, Error?) -> Void) {
        ensureBytes(2) { [weak self] error in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Connection deallocated"))
                return
            }
            if let error {
                completion(nil, error)
                return
            }

            let sizeBytes = self.takeBytes(2)
            let decodedSize = self.decodeResponseChunkSize(VMessCrypto.readUInt16BE(sizeBytes))
            let size = Int(decodedSize.size)
            let paddingLength = Int(decodedSize.padding)
            let overhead = self.session.security.aeadTagSize
            if size == overhead + paddingLength {
                completion(nil, nil)
                return
            }
            guard size >= overhead + paddingLength else {
                completion(nil, ProxyError.invalidResponse("Invalid VMess body chunk size"))
                return
            }

            self.ensureBytes(size) { [weak self] error in
                guard let self else {
                    completion(nil, ProxyError.connectionFailed("Connection deallocated"))
                    return
                }
                if let error {
                    completion(nil, error)
                    return
                }

                var chunk = self.takeBytes(size)
                do {
                    if paddingLength > 0 {
                        chunk.removeLast(paddingLength)
                    }
                    completion(try self.openChunk(chunk), nil)
                } catch {
                    completion(nil, error)
                }
            }
        }
    }

    // MARK: - Receive Buffer

    private func ensureBytes(_ count: Int, completion: @escaping (Error?) -> Void) {
        stateLock.lock()
        if availableBytesLocked >= count {
            stateLock.unlock()
            completion(nil)
            return
        }
        stateLock.unlock()

        inner.receiveRaw { [weak self] data, error in
            guard let self else {
                completion(ProxyError.connectionFailed("Connection deallocated"))
                return
            }
            if let error {
                completion(error)
                return
            }
            guard let data, !data.isEmpty else {
                completion(ProxyError.invalidResponse("VMess connection closed while reading"))
                return
            }

            self.stateLock.lock()
            self.receiveBuffer.append(data)
            self.stateLock.unlock()
            self.ensureBytes(count, completion: completion)
        }
    }

    private var availableBytesLocked: Int {
        receiveBuffer.count - receiveBufferOffset
    }

    private func takeBytes(_ count: Int) -> Data {
        stateLock.lock()
        let start = receiveBufferOffset
        let end = start + count
        let data = Data(receiveBuffer[start..<end])
        receiveBufferOffset = end
        compactReceiveBufferLocked()
        stateLock.unlock()
        return data
    }

    private func takeBufferedRemainder() -> Data? {
        stateLock.lock()
        guard availableBytesLocked > 0 else {
            stateLock.unlock()
            return nil
        }
        let data = Data(receiveBuffer[receiveBufferOffset..<receiveBuffer.count])
        receiveBuffer.removeAll(keepingCapacity: true)
        receiveBufferOffset = 0
        stateLock.unlock()
        return data
    }

    private func compactReceiveBufferLocked() {
        if receiveBufferOffset > 8192 {
            receiveBuffer.removeSubrange(0..<receiveBufferOffset)
            receiveBufferOffset = 0
        } else if receiveBufferOffset == receiveBuffer.count {
            receiveBuffer.removeAll(keepingCapacity: true)
            receiveBufferOffset = 0
        }
    }
}
