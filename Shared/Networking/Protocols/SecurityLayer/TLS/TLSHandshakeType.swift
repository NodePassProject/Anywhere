//
//  TLSHandshakeType.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

nonisolated enum TLSHandshakeType {
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
