//
//  TLS12ServerHandshakeState.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation

struct TLS12ServerHandshakeState {
    var transcript: Data = Data()
    var masterSecret: Data?
    var keys: TLS12HandshakeKeys?
    var clientRandom: Data?
    var serverRandom: Data?
    var extendedMasterSecret: Bool = false
    var receivedCCS: Bool = false
}
