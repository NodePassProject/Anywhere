//
//  TLS12HandshakeKeys.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation

struct TLS12HandshakeKeys {
    let clientMACKey: Data
    let serverMACKey: Data
    let clientKey: Data
    let serverKey: Data
    let clientIV: Data
    let serverIV: Data
}
