import Foundation
import CryptoKit

enum TLSCipherSuite {
    // TLS 1.3
    static let TLS_AES_128_GCM_SHA256: UInt16 = 0x1301
    static let TLS_AES_256_GCM_SHA384: UInt16 = 0x1302
    static let TLS_CHACHA20_POLY1305_SHA256: UInt16 = 0x1303

    // TLS 1.2 ECDHE AEAD
    static let TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: UInt16 = 0xC02B
    static let TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: UInt16 = 0xC02C
    static let TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: UInt16 = 0xC02F
    static let TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: UInt16 = 0xC030
    static let TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: UInt16 = 0xCCA9
    static let TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: UInt16 = 0xCCA8

    // TLS 1.2 ECDHE CBC
    static let TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: UInt16 = 0xC009
    static let TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: UInt16 = 0xC00A
    static let TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: UInt16 = 0xC013
    static let TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: UInt16 = 0xC014
    static let TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: UInt16 = 0xC023
    static let TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: UInt16 = 0xC024
    static let TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: UInt16 = 0xC027
    static let TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: UInt16 = 0xC028

    // TLS 1.2 RSA AEAD
    static let TLS_RSA_WITH_AES_128_GCM_SHA256: UInt16 = 0x009C
    static let TLS_RSA_WITH_AES_256_GCM_SHA384: UInt16 = 0x009D

    // TLS 1.2 RSA CBC
    static let TLS_RSA_WITH_AES_128_CBC_SHA: UInt16 = 0x002F
    static let TLS_RSA_WITH_AES_256_CBC_SHA: UInt16 = 0x0035
    static let TLS_RSA_WITH_AES_128_CBC_SHA256: UInt16 = 0x003C
    static let TLS_RSA_WITH_AES_256_CBC_SHA256: UInt16 = 0x003D

    // MARK: - Cipher Suite Properties

    static func isECDHE(_ suite: UInt16) -> Bool {
        switch suite {
        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
             TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
             TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
             TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
             TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
             TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
             TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            return true
        default:
            return false
        }
    }

    static func isAEAD(_ suite: UInt16) -> Bool {
        switch suite {
        case TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
             TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
             TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
             TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
             TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384:
            return true
        default:
            return false
        }
    }

    static func isChaCha20(_ suite: UInt16) -> Bool {
        switch suite {
        case TLS_CHACHA20_POLY1305_SHA256,
             TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            return true
        default:
            return false
        }
    }

    static func usesSHA384(_ suite: UInt16) -> Bool {
        switch suite {
        case TLS_AES_256_GCM_SHA384,
             TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
             TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
             TLS_RSA_WITH_AES_256_GCM_SHA384:
            return true
        default:
            return false
        }
    }

    static func keyLength(_ suite: UInt16) -> Int {
        switch suite {
        case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
             TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
             TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
             TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
             TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA256,
             TLS_RSA_WITH_AES_256_GCM_SHA384,
             TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256:
            return 32
        default:
            return 16
        }
    }

    static func ivLength(_ suite: UInt16) -> Int {
        if isChaCha20(suite) { return 12 }
        if isAEAD(suite) { return 4 }
        return 16
    }

    static func macLength(_ suite: UInt16) -> Int {
        if isAEAD(suite) { return 0 }
        if usesSHA384(suite) { return 48 }
        switch suite {
        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
             TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA256:
            return 32
        default:
            return 20
        }
    }
}

enum TLSContentType {
    static let invalid: UInt8 = 0
    static let changeCipherSpec: UInt8 = 20
    static let alert: UInt8 = 21
    static let handshake: UInt8 = 22
    static let applicationData: UInt8 = 23
}

enum TLSHandshakeType {
    static let clientHello: UInt8 = 1
    static let serverHello: UInt8 = 2
    static let newSessionTicket: UInt8 = 4
    static let endOfEarlyData: UInt8 = 5
    static let encryptedExtensions: UInt8 = 8
    static let certificate: UInt8 = 11
    static let serverKeyExchange: UInt8 = 12
    static let certificateRequest: UInt8 = 13
    static let serverHelloDone: UInt8 = 14
    static let certificateVerify: UInt8 = 15
    static let clientKeyExchange: UInt8 = 16
    static let finished: UInt8 = 20
    static let keyUpdate: UInt8 = 24
    static let compressedCertificate: UInt8 = 25
    static let messageHash: UInt8 = 254
}

enum TLSRandom {
    static let helloRetryRequest = Data([
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ])
}

enum TLSExtensionType {
    static let serverName: UInt16 = 0
    static let supportedGroups: UInt16 = 10
    static let signatureAlgorithms: UInt16 = 13
    static let applicationLayerProtocolNegotiation: UInt16 = 16
    static let extendedMasterSecret: UInt16 = 23
    static let preSharedKey: UInt16 = 41
    static let earlyData: UInt16 = 42
    static let supportedVersions: UInt16 = 43
    static let preSharedKeyKexModes: UInt16 = 45
    static let keyShare: UInt16 = 51
    static let quicTransportParameters: UInt16 = 57
    static let ticketRequest: UInt16 = 58
    static let renegotiationInfo: UInt16 = 0xFF01
}

enum TLSNamedGroup {
    static let secp256: UInt16 = 0x0017
    static let secp384: UInt16 = 0x0018
    static let x25519: UInt16 = 0x001D
    static let x25519MLKEM768: UInt16 = 0x11EC
}

enum TLSAlertLevel {
    static let warning: UInt8 = 1
    static let fatal: UInt8 = 2
}

enum TLSAlertDescription {
    static let closeNotify: UInt8 = 0
    static let unexpectedMessage: UInt8 = 10
    static let badRecordMac: UInt8 = 20
    static let recordOverflow: UInt8 = 22
    static let handshakeFailure: UInt8 = 40
    static let badCertificate: UInt8 = 42
    static let unsupportedCertificate: UInt8 = 43
    static let certificateRevoked: UInt8 = 44
    static let certificateExpired: UInt8 = 45
    static let certificateUnknown: UInt8 = 46
    static let illegalParameter: UInt8 = 47
    static let unknownCA: UInt8 = 48
    static let accessDenied: UInt8 = 49
    static let decodeError: UInt8 = 50
    static let decryptError: UInt8 = 51
    static let protocolVersion: UInt8 = 70
    static let insufficientSecurity: UInt8 = 71
    static let internalError: UInt8 = 80
    static let inappropriateFallback: UInt8 = 86
    static let userCanceled: UInt8 = 90
    static let missingExtension: UInt8 = 109
    static let unsupportedExtension: UInt8 = 110
    static let unrecognizedName: UInt8 = 112
    static let badCertificateStatusResponse: UInt8 = 113
    static let unknownPskIdentity: UInt8 = 115
    static let certificateRequired: UInt8 = 116
    static let noApplicationProtocol: UInt8 = 120
}

enum TLSSignatureScheme {
    static let rsa_pkcs1_sha1: UInt16 = 0x0201
    static let ecdsa_sha1: UInt16 = 0x0203
    static let rsa_pkcs1_sha256: UInt16 = 0x0401
    static let rsa_pkcs1_sha384: UInt16 = 0x0501
    static let rsa_pkcs1_sha512: UInt16 = 0x0601
    static let ecdsa_secp256r1_sha256: UInt16 = 0x0403
    static let ecdsa_secp384r1_sha384: UInt16 = 0x0503
    static let ecdsa_secp521r1_sha512: UInt16 = 0x0603
    static let rsa_pss_rsae_sha256: UInt16 = 0x0804
    static let rsa_pss_rsae_sha384: UInt16 = 0x0805
    static let rsa_pss_rsae_sha512: UInt16 = 0x0806
}

/// TLS 1.3 handshake traffic keys
struct TLSHandshakeKeys {
    let clientKey: Data
    let clientIV: Data
    let serverKey: Data
    let serverIV: Data
    let clientTrafficSecret: Data
    let serverTrafficSecret: Data
}

/// TLS 1.3 application traffic keys
struct TLSApplicationKeys {
    let clientKey: Data
    let clientIV: Data
    let serverKey: Data
    let serverIV: Data
}

/// Client-side handshake-time TLS 1.3 state; populated incrementally, then reset once
/// the application keys move into the long-lived record connection.
struct TLS13HandshakeState {
    /// Set when the ServerHello cipher suite is parsed.
    var keyDerivation: TLS13KeyDerivation?

    /// Held until the application keys are derived from the full transcript.
    var handshakeSecret: Data?

    /// Handshake-traffic keys; decrypt Certificate/CertificateVerify/Finished.
    var handshakeKeys: TLSHandshakeKeys?

    /// Derived after the server Finished is verified.
    var applicationKeys: TLSApplicationKeys?

    /// Running handshake transcript, updated as each message is consumed.
    var handshakeTranscript: Data?

    var serverHandshakeSeqNum: UInt64 = 0
}

/// Manages the TLS 1.3 session key schedule and exposes the derived secrets to the rest of the handshake.
struct TLS13KeyDerivation {
    let cipherSuite: UInt16

    init(cipherSuite: UInt16 = TLSCipherSuite.TLS_AES_128_GCM_SHA256) {
        self.cipherSuite = cipherSuite
    }

    var hashLength: Int {
        return cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 ? 48 : 32
    }

    var keyLength: Int {
        switch cipherSuite {
        case TLSCipherSuite.TLS_AES_256_GCM_SHA384,
             TLSCipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            return 32
        default:
            return 16
        }
    }

    // MARK: - HKDF Primitives

    func extract(inputKeyMaterial ikm: Data, salt: Data) -> (prk: Data, key: SymmetricKey) {
        let saltData = salt.isEmpty ? Data(repeating: 0, count: hashLength) : salt
        let key = SymmetricKey(data: saltData)

        let prk: Data
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            prk = Data(HMAC<SHA384>.authenticationCode(for: ikm, using: key))
        } else {
            prk = Data(HMAC<SHA256>.authenticationCode(for: ikm, using: key))
        }
        return (prk, SymmetricKey(data: prk))
    }

    func expand(pseudoRandomKey: SymmetricKey, info: Data, outputByteCount: Int) -> Data {
        var output = Data(capacity: outputByteCount + hashLength)
        var t = Data()
        var counter: UInt8 = 1
        var input = Data(capacity: hashLength + info.count + 1)

        while output.count < outputByteCount {
            input.removeAll(keepingCapacity: true)
            input.append(t)
            input.append(info)
            input.append(counter)

            if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
                t = Data(HMAC<SHA384>.authenticationCode(for: input, using: pseudoRandomKey))
            } else {
                t = Data(HMAC<SHA256>.authenticationCode(for: input, using: pseudoRandomKey))
            }
            output.append(t)
            counter += 1
        }

        return Data(output.prefix(outputByteCount))
    }

    func expandLabel(secret: SymmetricKey, label: String, context: Data, length: Int) -> Data {
        // We need to build HkdfLabel:
        //
        // struct {
        //   uint16 length = Length;
        //   opaque label<7..255> = "tls13 " + Label;
        //   opaque context<0..255> = Context;
        // } HkdfLabel
        let fullLabel = "tls13 " + label
        var hkdfLabel = Data()
        hkdfLabel.append(UInt8((length >> 8) & 0xFF))
        hkdfLabel.append(UInt8(length & 0xFF))
        hkdfLabel.append(UInt8(fullLabel.count))
        hkdfLabel.append(contentsOf: fullLabel.utf8)
        hkdfLabel.append(UInt8(context.count))
        hkdfLabel.append(context)
        return expand(pseudoRandomKey: secret, info: hkdfLabel, outputByteCount: length)
    }

    func deriveSecret(secret: SymmetricKey, label: String, messages: Data) -> Data {
        let hashData: Data
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            hashData = Data(SHA384.hash(data: messages))
        } else {
            hashData = Data(SHA256.hash(data: messages))
        }
        return expandLabel(secret: secret, label: label, context: hashData, length: hashLength)
    }

    // MARK: - Public API

    func transcriptHash(_ messages: Data) -> Data {
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            return Data(SHA384.hash(data: messages))
        } else {
            return Data(SHA256.hash(data: messages))
        }
    }

    /// Derive handshake-traffic keys and return the handshake secret.
    /// `psk` is for session resumption; `nil` means full handshake (all-zero IKM).
    func deriveHandshakeKeys(sharedSecret: Data, transcript: Data, psk: Data? = nil) -> (handshakeSecret: Data, keys: TLSHandshakeKeys) {
        let earlyIKM = psk ?? Data(repeating: 0, count: hashLength)
        let (_, earlyKey) = extract(inputKeyMaterial: earlyIKM, salt: Data())
        let derivedEarly = deriveSecret(secret: earlyKey, label: "derived", messages: Data())
        let (hsPRK, hsKey) = extract(inputKeyMaterial: sharedSecret, salt: derivedEarly)

        let clientHTS = deriveSecret(secret: hsKey, label: "c hs traffic", messages: transcript)
        let clientHTSKey = SymmetricKey(data: clientHTS)
        let clientKey = expandLabel(secret: clientHTSKey, label: "key", context: Data(), length: keyLength)
        let clientIV = expandLabel(secret: clientHTSKey, label: "iv", context: Data(), length: 12)

        let serverHTS = deriveSecret(secret: hsKey, label: "s hs traffic", messages: transcript)
        let serverHTSKey = SymmetricKey(data: serverHTS)
        let serverKey = expandLabel(secret: serverHTSKey, label: "key", context: Data(), length: keyLength)
        let serverIV = expandLabel(secret: serverHTSKey, label: "iv", context: Data(), length: 12)

        let keys = TLSHandshakeKeys(
            clientKey: clientKey, clientIV: clientIV,
            serverKey: serverKey, serverIV: serverIV,
            clientTrafficSecret: clientHTS,
            serverTrafficSecret: serverHTS
        )
        return (hsPRK, keys)
    }

    /// Derive application keys from the full transcript (including server Finished)
    func deriveApplicationKeys(handshakeSecret: Data, fullTranscript: Data) -> TLSApplicationKeys {
        let hsKey = SymmetricKey(data: handshakeSecret)
        let derivedHS = deriveSecret(secret: hsKey, label: "derived", messages: Data())
        let (_, masterKey) = extract(inputKeyMaterial: Data(repeating: 0, count: hashLength), salt: derivedHS)

        let clientATS = deriveSecret(secret: masterKey, label: "c ap traffic", messages: fullTranscript)
        let clientATSKey = SymmetricKey(data: clientATS)
        let clientKey = expandLabel(secret: clientATSKey, label: "key", context: Data(), length: keyLength)
        let clientIV = expandLabel(secret: clientATSKey, label: "iv", context: Data(), length: 12)

        let serverATS = deriveSecret(secret: masterKey, label: "s ap traffic", messages: fullTranscript)
        let serverATSKey = SymmetricKey(data: serverATS)
        let serverKey = expandLabel(secret: serverATSKey, label: "key", context: Data(), length: keyLength)
        let serverIV = expandLabel(secret: serverATSKey, label: "iv", context: Data(), length: 12)

        return TLSApplicationKeys(
            clientKey: clientKey, clientIV: clientIV,
            serverKey: serverKey, serverIV: serverIV
        )
    }

    /// The expected payload of Finished for the given traffic secret (client or server).
    func finishedPayload(trafficSecret: Data, transcript: Data) -> Data {
        let tsKey = SymmetricKey(data: trafficSecret)
        let finishedKey = expandLabel(secret: tsKey, label: "finished", context: Data(), length: hashLength)
        let transcriptHash = self.transcriptHash(transcript)

        let key = SymmetricKey(data: finishedKey)
        if cipherSuite == TLSCipherSuite.TLS_AES_256_GCM_SHA384 {
            return Data(HMAC<SHA384>.authenticationCode(for: transcriptHash, using: key))
        } else {
            return Data(HMAC<SHA256>.authenticationCode(for: transcriptHash, using: key))
        }
    }

    /// The expected payload of client Finished.
    func clientFinishedPayload(clientTrafficSecret: Data, transcript: Data) -> Data {
        finishedPayload(trafficSecret: clientTrafficSecret, transcript: transcript)
    }
}

// MARK: - Server-Side Helpers

/// Server-side TLS 1.3 handshake state; the server encrypts with serverKey and
/// decrypts with clientKey.
struct TLS13ServerHandshakeState {
    var keyDerivation: TLS13KeyDerivation?
    var handshakeSecret: Data?
    var handshakeKeys: TLSHandshakeKeys?
    var applicationKeys: TLSApplicationKeys?
    /// Running transcript: ClientHello || (HRR || ClientHello2) || ServerHello || ...
    var transcript: Data = Data()
    var clientHandshakeSeqNum: UInt64 = 0
    var serverHandshakeSeqNum: UInt64 = 0
}

extension TLS13KeyDerivation {
    /// The expected payload of server Finished.
    func serverFinishedPayload(serverTrafficSecret: Data, transcript: Data) -> Data {
        finishedPayload(trafficSecret: serverTrafficSecret, transcript: transcript)
    }
}
