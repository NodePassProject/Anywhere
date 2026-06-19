//
//  TLSSignatureScheme.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

nonisolated enum TLSSignatureScheme {
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
