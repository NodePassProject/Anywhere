//
//  QUICTLSProvider.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

public enum QUICHandshakeAction: Sendable {
    case sendCryptoData(Data, level: QUICEncryptionLevel)
    case installHandshakeKeys(cipherSuite: QUICCipherSuite, readSecret: Data, writeSecret: Data)
    case installApplicationKeys(cipherSuite: QUICCipherSuite, readSecret: Data, writeSecret: Data)
    case setRemoteTransportParameters(Data)
    case verifyPeer(certificates: [Data])
    case handshakeComplete
}

public protocol QUICTLSProvider: AnyObject {
    func startHandshake(localTransportParameters: Data) throws -> [QUICHandshakeAction]
    func receiveCryptoData(_ data: Data, at level: QUICEncryptionLevel) throws -> [QUICHandshakeAction]
    func exportKeyingMaterial(label: String, context: Data, length: Int) throws -> Data
    func completePeerVerification(error: (any Error)?) throws -> [QUICHandshakeAction]
}

extension QUICTLSProvider {
    public func exportKeyingMaterial(label: String, context: Data, length: Int) throws -> Data {
        throw QUICError.exporterUnavailable
    }

    public func completePeerVerification(error: (any Error)?) throws -> [QUICHandshakeAction] {
        throw QUICError.invalidState
    }
}
