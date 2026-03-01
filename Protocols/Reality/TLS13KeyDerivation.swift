//
//  TLS13KeyDerivation.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
#if !NETWORK_EXTENSION
import CryptoKit
#endif

/// TLS 1.3 cipher suite constants
enum TLSCipherSuite {
    static let TLS_AES_128_GCM_SHA256: UInt16 = 0x1301
    static let TLS_AES_256_GCM_SHA384: UInt16 = 0x1302
    static let TLS_CHACHA20_POLY1305_SHA256: UInt16 = 0x1303
}

/// TLS 1.3 handshake traffic keys
struct TLSHandshakeKeys {
    let clientKey: Data
    let clientIV: Data
    let serverKey: Data
    let serverIV: Data
    let clientTrafficSecret: Data
}

/// TLS 1.3 application traffic keys
struct TLSApplicationKeys {
    let clientKey: Data
    let clientIV: Data
    let serverKey: Data
    let serverIV: Data
}

/// TLS 1.3 key derivation utilities
struct TLS13KeyDerivation {
    let cipherSuite: UInt16

    init(cipherSuite: UInt16 = TLSCipherSuite.TLS_AES_128_GCM_SHA256) {
        self.cipherSuite = cipherSuite
    }

    /// Get hash output length based on cipher suite
    var hashLength: Int {
        return cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 ? 48 : 32
    }

    /// Get encryption key length based on cipher suite
    var keyLength: Int {
        return cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 ? 32 : 16
    }

#if NETWORK_EXTENSION

    // MARK: - Network Extension (CommonCrypto C)

    /// Derive TLS 1.3 handshake keys from shared secret
    func deriveHandshakeKeys(sharedSecret: Data, transcript: Data) -> (handshakeSecret: Data, keys: TLSHandshakeKeys) {
        var hsSecret = Data(count: hashLength)
        var clientKey = Data(count: keyLength)
        var clientIV = Data(count: 12)
        var serverKey = Data(count: keyLength)
        var serverIV = Data(count: 12)
        var clientTrafficSecret = Data(count: hashLength)

        hsSecret.withUnsafeMutableBytes { hsPtr in
            clientKey.withUnsafeMutableBytes { ckPtr in
                clientIV.withUnsafeMutableBytes { ciPtr in
                    serverKey.withUnsafeMutableBytes { skPtr in
                        serverIV.withUnsafeMutableBytes { siPtr in
                            clientTrafficSecret.withUnsafeMutableBytes { ctsPtr in
                                sharedSecret.withUnsafeBytes { ssPtr in
                                    transcript.withUnsafeBytes { tPtr in
                                        tls13_derive_handshake_keys(
                                            cipherSuite,
                                            ssPtr.bindMemory(to: UInt8.self).baseAddress!,
                                            sharedSecret.count,
                                            tPtr.bindMemory(to: UInt8.self).baseAddress!,
                                            transcript.count,
                                            hsPtr.bindMemory(to: UInt8.self).baseAddress!,
                                            ckPtr.bindMemory(to: UInt8.self).baseAddress!,
                                            ciPtr.bindMemory(to: UInt8.self).baseAddress!,
                                            skPtr.bindMemory(to: UInt8.self).baseAddress!,
                                            siPtr.bindMemory(to: UInt8.self).baseAddress!,
                                            ctsPtr.bindMemory(to: UInt8.self).baseAddress!
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let keys = TLSHandshakeKeys(
            clientKey: clientKey,
            clientIV: clientIV,
            serverKey: serverKey,
            serverIV: serverIV,
            clientTrafficSecret: clientTrafficSecret
        )
        return (hsSecret, keys)
    }

    /// Derive application keys from the full transcript (including server Finished)
    func deriveApplicationKeys(handshakeSecret: Data, fullTranscript: Data) -> TLSApplicationKeys {
        var clientKey = Data(count: keyLength)
        var clientIV = Data(count: 12)
        var serverKey = Data(count: keyLength)
        var serverIV = Data(count: 12)

        clientKey.withUnsafeMutableBytes { ckPtr in
            clientIV.withUnsafeMutableBytes { ciPtr in
                serverKey.withUnsafeMutableBytes { skPtr in
                    serverIV.withUnsafeMutableBytes { siPtr in
                        handshakeSecret.withUnsafeBytes { hsPtr in
                            fullTranscript.withUnsafeBytes { tPtr in
                                tls13_derive_application_keys(
                                    cipherSuite,
                                    hsPtr.bindMemory(to: UInt8.self).baseAddress!,
                                    handshakeSecret.count,
                                    tPtr.bindMemory(to: UInt8.self).baseAddress!,
                                    fullTranscript.count,
                                    ckPtr.bindMemory(to: UInt8.self).baseAddress!,
                                    ciPtr.bindMemory(to: UInt8.self).baseAddress!,
                                    skPtr.bindMemory(to: UInt8.self).baseAddress!,
                                    siPtr.bindMemory(to: UInt8.self).baseAddress!
                                )
                            }
                        }
                    }
                }
            }
        }

        return TLSApplicationKeys(
            clientKey: clientKey,
            clientIV: clientIV,
            serverKey: serverKey,
            serverIV: serverIV
        )
    }

    /// Compute Client Finished verify data
    func computeFinishedVerifyData(clientTrafficSecret: Data, transcript: Data) -> Data {
        var verifyData = Data(count: hashLength)

        verifyData.withUnsafeMutableBytes { vdPtr in
            clientTrafficSecret.withUnsafeBytes { ctsPtr in
                transcript.withUnsafeBytes { tPtr in
                    tls13_compute_finished(
                        cipherSuite,
                        ctsPtr.bindMemory(to: UInt8.self).baseAddress!,
                        clientTrafficSecret.count,
                        tPtr.bindMemory(to: UInt8.self).baseAddress!,
                        transcript.count,
                        vdPtr.bindMemory(to: UInt8.self).baseAddress!
                    )
                }
            }
        }

        return verifyData
    }

    /// Compute transcript hash
    func transcriptHash(_ messages: Data) -> Data {
        var hash = Data(count: hashLength)

        hash.withUnsafeMutableBytes { hPtr in
            messages.withUnsafeBytes { mPtr in
                tls13_transcript_hash(
                    cipherSuite,
                    mPtr.bindMemory(to: UInt8.self).baseAddress!,
                    messages.count,
                    hPtr.bindMemory(to: UInt8.self).baseAddress!
                )
            }
        }

        return hash
    }

#else

    // MARK: - Main App (CryptoKit fallback)

    func hkdfExtract(salt: Data, ikm: Data) -> Data {
        let saltData = salt.isEmpty ? Data(repeating: 0, count: hashLength) : salt
        let key = SymmetricKey(data: saltData)

        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            return Data(HMAC<SHA384>.authenticationCode(for: ikm, using: key))
        } else {
            return Data(HMAC<SHA256>.authenticationCode(for: ikm, using: key))
        }
    }

    func hkdfExpand(prk: Data, info: Data, length: Int) -> Data {
        let key = SymmetricKey(data: prk)
        var output = Data()
        var t = Data()
        var counter: UInt8 = 1

        while output.count < length {
            var input = t
            input.append(info)
            input.append(counter)

            if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
                t = Data(HMAC<SHA384>.authenticationCode(for: input, using: key))
            } else {
                t = Data(HMAC<SHA256>.authenticationCode(for: input, using: key))
            }
            output.append(t)
            counter += 1
        }

        return Data(output.prefix(length))
    }

    func hkdfExpandLabel(secret: Data, label: String, context: Data, length: Int) -> Data {
        let fullLabel = "tls13 " + label
        var hkdfLabel = Data()
        hkdfLabel.append(UInt8((length >> 8) & 0xFF))
        hkdfLabel.append(UInt8(length & 0xFF))
        hkdfLabel.append(UInt8(fullLabel.count))
        hkdfLabel.append(contentsOf: fullLabel.utf8)
        hkdfLabel.append(UInt8(context.count))
        hkdfLabel.append(context)
        return hkdfExpand(prk: secret, info: hkdfLabel, length: length)
    }

    func deriveSecret(secret: Data, label: String, messages: Data) -> Data {
        let hashData: Data
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            hashData = Data(SHA384.hash(data: messages))
        } else {
            hashData = Data(SHA256.hash(data: messages))
        }
        return hkdfExpandLabel(secret: secret, label: label, context: hashData, length: hashLength)
    }

    func transcriptHash(_ messages: Data) -> Data {
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            return Data(SHA384.hash(data: messages))
        } else {
            return Data(SHA256.hash(data: messages))
        }
    }

    func deriveHandshakeKeys(sharedSecret: Data, transcript: Data) -> (handshakeSecret: Data, keys: TLSHandshakeKeys) {
        let earlySecret = hkdfExtract(salt: Data(), ikm: Data(repeating: 0, count: hashLength))
        let derivedEarly = deriveSecret(secret: earlySecret, label: "derived", messages: Data())
        let handshakeSecret = hkdfExtract(salt: derivedEarly, ikm: sharedSecret)

        let clientHTS = deriveSecret(secret: handshakeSecret, label: "c hs traffic", messages: transcript)
        let clientKey = hkdfExpandLabel(secret: clientHTS, label: "key", context: Data(), length: keyLength)
        let clientIV = hkdfExpandLabel(secret: clientHTS, label: "iv", context: Data(), length: 12)

        let serverHTS = deriveSecret(secret: handshakeSecret, label: "s hs traffic", messages: transcript)
        let serverKey = hkdfExpandLabel(secret: serverHTS, label: "key", context: Data(), length: keyLength)
        let serverIV = hkdfExpandLabel(secret: serverHTS, label: "iv", context: Data(), length: 12)

        let keys = TLSHandshakeKeys(
            clientKey: clientKey, clientIV: clientIV,
            serverKey: serverKey, serverIV: serverIV,
            clientTrafficSecret: clientHTS
        )
        return (handshakeSecret, keys)
    }

    func deriveApplicationKeys(handshakeSecret: Data, fullTranscript: Data) -> TLSApplicationKeys {
        let derivedHS = deriveSecret(secret: handshakeSecret, label: "derived", messages: Data())
        let masterSecret = hkdfExtract(salt: derivedHS, ikm: Data(repeating: 0, count: hashLength))

        let clientATS = deriveSecret(secret: masterSecret, label: "c ap traffic", messages: fullTranscript)
        let clientKey = hkdfExpandLabel(secret: clientATS, label: "key", context: Data(), length: keyLength)
        let clientIV = hkdfExpandLabel(secret: clientATS, label: "iv", context: Data(), length: 12)

        let serverATS = deriveSecret(secret: masterSecret, label: "s ap traffic", messages: fullTranscript)
        let serverKey = hkdfExpandLabel(secret: serverATS, label: "key", context: Data(), length: keyLength)
        let serverIV = hkdfExpandLabel(secret: serverATS, label: "iv", context: Data(), length: 12)

        return TLSApplicationKeys(
            clientKey: clientKey, clientIV: clientIV,
            serverKey: serverKey, serverIV: serverIV
        )
    }

    func computeFinishedVerifyData(clientTrafficSecret: Data, transcript: Data) -> Data {
        let finishedKey = hkdfExpandLabel(secret: clientTrafficSecret, label: "finished", context: Data(), length: hashLength)
        let transcriptHash = self.transcriptHash(transcript)

        let key = SymmetricKey(data: finishedKey)
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            return Data(HMAC<SHA384>.authenticationCode(for: transcriptHash, using: key))
        } else {
            return Data(HMAC<SHA256>.authenticationCode(for: transcriptHash, using: key))
        }
    }

#endif
}
