//
//  VLESSEncryptionCTR.swift
//  Anywhere
//
//  Created by NodePassProject on 5/13/26.
//

import Foundation
import CommonCrypto

nonisolated final class VLESSEncryptionCTR {
    private let cryptor: CCCryptorRef

    init(key: Data, iv: Data) throws {
        guard iv.count == 16 else {
            throw AnywhereError.proxy(.vlessEncryption, .protocolViolation(detail: "framing: VLESS CTR IV must be 16 bytes, got \(iv.count)"))
        }
        let derivedKey = BLAKE3Hasher.deriveKey(context: "VLESS", input: key, count: 32)

        var ref: CCCryptorRef?
        let status = derivedKey.withUnsafeBytes { keyPtr -> CCCryptorStatus in
            iv.withUnsafeBytes { ivPtr in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt),
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivPtr.baseAddress,
                    keyPtr.baseAddress,
                    32,
                    nil, 0,
                    0,
                    CCModeOptions(kCCModeOptionCTR_BE),
                    &ref
                )
            }
        }
        guard status == kCCSuccess, let ref else {
            throw AnywhereError.proxy(.vlessEncryption, .protocolViolation(detail: "framing: CCCryptorCreateWithMode failed: \(status)"))
        }
        self.cryptor = ref
    }

    deinit {
        CCCryptorRelease(cryptor)
    }
    
    func process(_ data: Data) -> Data {
        if data.isEmpty { return data }
        let count = data.count
        var output = Data(count: count)
        var dataOutMoved: Int = 0
        _ = output.withUnsafeMutableBytes { outPtr -> CCCryptorStatus in
            data.withUnsafeBytes { inPtr in
                CCCryptorUpdate(
                    cryptor,
                    inPtr.baseAddress, count,
                    outPtr.baseAddress, count,
                    &dataOutMoved
                )
            }
        }
        return output
    }
    
    func processInPlace(_ bytes: inout [UInt8], range: Range<Int>) {
        if range.isEmpty { return }
        var dataOutMoved: Int = 0
        bytes.withUnsafeMutableBytes { buffer in
            let base = buffer.baseAddress! + range.lowerBound
            _ = CCCryptorUpdate(
                cryptor,
                base, range.count,
                base, range.count,
                &dataOutMoved
            )
        }
    }
}
