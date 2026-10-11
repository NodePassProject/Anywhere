//
//  KeyDerivation.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import CryptoKit
import Foundation

enum KeyDerivation {
    static let initialSaltV1: [UInt8] = [
        0x38, 0x76, 0x2C, 0xF7, 0xF5, 0x59, 0x34, 0xB3, 0x4D, 0x17,
        0x9A, 0xE6, 0xA4, 0xC8, 0x0C, 0xAD, 0xCC, 0xBB, 0x7F, 0x0A,
    ]

    static func extract(salt: [UInt8], inputKeyMaterial: [UInt8], hash: HashAlgorithm) -> [UInt8] {
        switch hash {
        case .sha256:
            let key = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: inputKeyMaterial), salt: salt)
            return key.withUnsafeBytes { Array($0) }
        case .sha384:
            let key = HKDF<SHA384>.extract(inputKeyMaterial: SymmetricKey(data: inputKeyMaterial), salt: salt)
            return key.withUnsafeBytes { Array($0) }
        }
    }

    static func expand(pseudoRandomKey: [UInt8], info: [UInt8], length: Int, hash: HashAlgorithm) -> [UInt8] {
        switch hash {
        case .sha256:
            let key = HKDF<SHA256>.expand(
                pseudoRandomKey: SymmetricKey(data: pseudoRandomKey),
                info: info,
                outputByteCount: length
            )
            return key.withUnsafeBytes { Array($0) }
        case .sha384:
            let key = HKDF<SHA384>.expand(
                pseudoRandomKey: SymmetricKey(data: pseudoRandomKey),
                info: info,
                outputByteCount: length
            )
            return key.withUnsafeBytes { Array($0) }
        }
    }

    static func hkdfLabel(length: Int, label: String, context: [UInt8]) -> [UInt8] {
        let fullLabel = Array("tls13 ".utf8) + Array(label.utf8)
        var info: [UInt8] = []
        info.reserveCapacity(4 + fullLabel.count + context.count)
        info.append(UInt8(length >> 8))
        info.append(UInt8(truncatingIfNeeded: length))
        info.append(UInt8(fullLabel.count))
        info.append(contentsOf: fullLabel)
        info.append(UInt8(context.count))
        info.append(contentsOf: context)
        return info
    }

    static func expandLabel(
        secret: [UInt8],
        label: String,
        context: [UInt8] = [],
        length: Int,
        hash: HashAlgorithm
    ) -> [UInt8] {
        return Self.expand(
            pseudoRandomKey: secret,
            info: Self.hkdfLabel(length: length, label: label, context: context),
            length: length,
            hash: hash
        )
    }

    static func initialSecrets(destinationID: QUICConnectionID) -> (client: [UInt8], server: [UInt8]) {
        let initialSecret = Self.extract(salt: Self.initialSaltV1, inputKeyMaterial: destinationID.bytes, hash: .sha256)
        let client = Self.expandLabel(secret: initialSecret, label: "client in", length: 32, hash: .sha256)
        let server = Self.expandLabel(secret: initialSecret, label: "server in", length: 32, hash: .sha256)
        return (client, server)
    }
}
