//
//  BLAKE3+ChainingValue.swift
//  BLAKE
//
//  Created by NodePassProject on 10/23/26.
//

extension BLAKE3 {
    struct ChainingValue: Sendable {
        var h0, h1, h2, h3, h4, h5, h6, h7: UInt32

        static var initializationVector: ChainingValue {
            ChainingValue(
                h0: 0x6A09_E667, h1: 0xBB67_AE85, h2: 0x3C6E_F372, h3: 0xA54F_F53A,
                h4: 0x510E_527F, h5: 0x9B05_688C, h6: 0x1F83_D9AB, h7: 0x5BE0_CD19
            )
        }

        func storeLittleEndianBytes(to bytes: UnsafeMutableRawPointer) {
            bytes.storeLittleEndian(h0, toByteOffset: 0)
            bytes.storeLittleEndian(h1, toByteOffset: 4)
            bytes.storeLittleEndian(h2, toByteOffset: 8)
            bytes.storeLittleEndian(h3, toByteOffset: 12)
            bytes.storeLittleEndian(h4, toByteOffset: 16)
            bytes.storeLittleEndian(h5, toByteOffset: 20)
            bytes.storeLittleEndian(h6, toByteOffset: 24)
            bytes.storeLittleEndian(h7, toByteOffset: 28)
        }
    }
}

extension BLAKE3.ChainingValue {
    init(littleEndianBytes bytes: UnsafeRawPointer) {
        self.init(
            h0: bytes.loadLittleEndian(fromByteOffset: 0, as: UInt32.self),
            h1: bytes.loadLittleEndian(fromByteOffset: 4, as: UInt32.self),
            h2: bytes.loadLittleEndian(fromByteOffset: 8, as: UInt32.self),
            h3: bytes.loadLittleEndian(fromByteOffset: 12, as: UInt32.self),
            h4: bytes.loadLittleEndian(fromByteOffset: 16, as: UInt32.self),
            h5: bytes.loadLittleEndian(fromByteOffset: 20, as: UInt32.self),
            h6: bytes.loadLittleEndian(fromByteOffset: 24, as: UInt32.self),
            h7: bytes.loadLittleEndian(fromByteOffset: 28, as: UInt32.self)
        )
    }
}
