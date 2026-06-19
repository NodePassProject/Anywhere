//
//  TLSAlertDescription.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

nonisolated enum TLSAlertDescription {
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
