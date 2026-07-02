//
//  HTTPMessage.swift
//  Anywhere
//
//  Created by NodePassProject on 6/4/26.
//

import Foundation

/// Scripts may only write back `body`; all other fields are read-only to them.
struct HTTPMessage {
    let phase: MITMPhase
    var method: String?
    var url: String?
    var originalUrl: String?
    var status: Int?
    var headers: [(name: String, value: String)]
    var body: Data
    let ruleSetID: UUID?
}
