//
//  NetworkContext.swift
//  Anywhere
//
//  Created by NodePassProject on 7/13/26.
//

import Foundation

nonisolated struct NetworkContext: Equatable {
    var isWiFi = false
    var isCellular = false
    var ssid: String?
}
