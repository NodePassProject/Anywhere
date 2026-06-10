//
//  HTTPMessage.swift
//  Anywhere
//
//  Created by NodePassProject on 6/4/26.
//

import Foundation

/// Protocol-agnostic in-flight message the HTTP/1 and HTTP/2 rewriters parse
/// into, scripts process, and the rewriters re-emit from. Only `body` is read
/// back from a script; `method`, `url`, `status`, and `headers` are read-only there.
struct HTTPMessage {
    let phase: MITMPhase
    var method: String?
    var url: String?
    var status: Int?
    var headers: [(name: String, value: String)]
    var body: Data
    let ruleSetID: UUID?
}
