//
//  TLSContentType.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

nonisolated enum TLSContentType {
    static let invalid: UInt8 = 0
    static let changeCipherSpec: UInt8 = 20
    static let alert: UInt8 = 21
    static let handshake: UInt8 = 22
    static let applicationData: UInt8 = 23
}
