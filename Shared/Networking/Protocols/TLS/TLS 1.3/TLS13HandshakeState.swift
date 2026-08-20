//
//  TLS13HandshakeState.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation

nonisolated struct TLS13HandshakeState {
    var keyDerivation: TLS13KeyDerivation?
    var handshakeSecret: Data?
    var handshakeKeys: TLS13HandshakeKeys?
    var applicationKeys: TLS13ApplicationKeys?
    var handshakeTranscript: Data?
    var serverHandshakeSeqNum: UInt64 = 0
    var transcriptBeforeCertVerify: Data?
    var certificateVerifySignature: Data?
    var certificateVerifyAlgorithm: UInt16 = 0
    var clientCertRequested = false
}
