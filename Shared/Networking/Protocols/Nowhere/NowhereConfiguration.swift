//
//  NowhereConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation

/// Configuration for a Nowhere QUIC session.
struct NowhereConfiguration: Hashable {
    let proxyHost: String
    let proxyPort: UInt16
    let key: String
}
