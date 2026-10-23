//
//  BLAKE2b+ChainingValue.swift
//  BLAKE
//
//  Created by NodePassProject on 10/23/26.
//

extension BLAKE2b {
    struct ChainingValue: Sendable {
        var h0, h1, h2, h3, h4, h5, h6, h7: UInt64

        static var initializationVector: ChainingValue {
            ChainingValue(
                h0: 0x6A09_E667_F3BC_C908, h1: 0xBB67_AE85_84CA_A73B,
                h2: 0x3C6E_F372_FE94_F82B, h3: 0xA54F_F53A_5F1D_36F1,
                h4: 0x510E_527F_ADE6_82D1, h5: 0x9B05_688C_2B3E_6C1F,
                h6: 0x1F83_D9AB_FB41_BD6B, h7: 0x5BE0_CD19_137E_2179
            )
        }

        func storeLittleEndianBytes(to bytes: UnsafeMutableRawPointer) {
            bytes.storeLittleEndian(h0, toByteOffset: 0)
            bytes.storeLittleEndian(h1, toByteOffset: 8)
            bytes.storeLittleEndian(h2, toByteOffset: 16)
            bytes.storeLittleEndian(h3, toByteOffset: 24)
            bytes.storeLittleEndian(h4, toByteOffset: 32)
            bytes.storeLittleEndian(h5, toByteOffset: 40)
            bytes.storeLittleEndian(h6, toByteOffset: 48)
            bytes.storeLittleEndian(h7, toByteOffset: 56)
        }
    }
}
