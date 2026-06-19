//
//  TLSExtensionType.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

nonisolated enum TLSExtensionType {
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
