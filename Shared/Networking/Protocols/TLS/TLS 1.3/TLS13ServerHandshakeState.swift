//
//  TLS13ServerHandshakeState.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation

struct TLS13ServerHandshakeState {
    var keyDerivation: TLS13KeyDerivation?
    var handshakeSecret: Data?
    var handshakeKeys: TLS13HandshakeKeys?
    var applicationKeys: TLS13ApplicationKeys?
    /// Running transcript: ClientHello || (HRR || ClientHello2) || ServerHello || ...
    var transcript: Data = Data()
    var clientHandshakeSeqNum: UInt64 = 0
    var serverHandshakeSeqNum: UInt64 = 0
}
