//
//  TLS13HandshakeState.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation

struct TLS13HandshakeState {
    /// Set when the ServerHello cipher suite is parsed.
    var keyDerivation: TLS13KeyDerivation?

    /// Held until the application keys are derived from the full transcript.
    var handshakeSecret: Data?

    /// Handshake-traffic keys; decrypt Certificate/CertificateVerify/Finished.
    var handshakeKeys: TLS13HandshakeKeys?

    /// Derived after the server Finished is verified.
    var applicationKeys: TLS13ApplicationKeys?

    var handshakeTranscript: Data?

    var serverHandshakeSeqNum: UInt64 = 0
}
