//
//  TLSRecordConnection+TLS13.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation
import CryptoKit
import CommonCrypto

extension TLSRecordConnection {

    // MARK: - TLS 1.3 Record Crypto

    func encryptTLS13Record(plaintext: Data, contentType: UInt8 = TLSContentType.applicationData) throws -> Data {
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

    func decryptTLS13Record(ciphertext: Data, header: Data, seqNum: UInt64) throws -> Data {
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
        let contentLen: ssize_t = decrypted.withUnsafeBytes { pointer -> ssize_t in
            let decryptedBytes = pointer.bindMemory(to: UInt8.self)
            var i = decryptedBytes.count - 1
            while i >= 0 && decryptedBytes[i] == 0 { i -= 1 }
            guard i >= 0 else { return -1 }
            innerContentType = decryptedBytes[i]
            return ssize_t(i)
        }

        guard contentLen >= 0 else {
            throw TLSRecordError.noContentTypeFound
        }

        // A KeyUpdate must rekey the read side here or every subsequent record fails AEAD
        // authentication (RFC 8446 §7.2).
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

    /// Runs on the receive path with `receiveLock` held (and never `seqLock`).
    private func handlePostHandshakeTLS13(_ messages: Data) {
        var i = messages.startIndex
        let end = messages.endIndex
        while i + 4 <= end {
            let type = messages[i]
            let length = Int(messages[i + 1]) << 16 | Int(messages[i + 2]) << 8 | Int(messages[i + 3])
            let bodyStart = i + 4
            let bodyEnd = bodyStart + length
            guard bodyEnd <= end else { break }

            if type == TLSHandshakeType.keyUpdate {
                // Peer switched its sending keys; advance ours for reading.
                rekeyIngress()
                // request_update == 1 ("update_requested") obliges us to KeyUpdate back.
                let requestUpdate = length >= 1 ? messages[bodyStart] : 0
                if requestUpdate == 1 {
                    keyUpdateResponsePending = true
                }
            }
            i = bodyEnd
        }
    }

    /// Ingress is the server keys for a client and the client keys for a server. No-op when the
    /// traffic secret is unavailable (e.g. TLS 1.2).
    private func rekeyIngress() {
        let keyDerivation = TLS13KeyDerivation(cipherSuite: cipherSuite)
        if direction == .server {
            guard let current = clientAppSecret else { return }
            let next = keyDerivation.nextApplicationGeneration(trafficSecret: current)
            seqLock.lock()
            clientAppSecret = next.secret
            clientKey = next.key
            clientIV = next.iv
            clientSymmetricKey = SymmetricKey(data: next.key)
            clientSeqNum = 0
            seqLock.unlock()
        } else {
            guard let current = serverAppSecret else { return }
            let next = keyDerivation.nextApplicationGeneration(trafficSecret: current)
            seqLock.lock()
            serverAppSecret = next.secret
            serverKey = next.key
            serverIV = next.iv
            serverSymmetricKey = SymmetricKey(data: next.key)
            serverSeqNum = 0
            seqLock.unlock()
        }
    }

    /// Sends our KeyUpdate using the *current* write keys, then advances egress. Held under
    /// `sendLock` so the key switch is atomic with respect to application sends; called only after
    /// `receiveLock` has been released.
    func sendKeyUpdateResponseAndRekeyEgress() {
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
}
