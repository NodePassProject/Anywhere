//
//  LatencyResult.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
//

import Foundation

nonisolated enum LatencyResult: Sendable, Hashable {
    case testing
    case success(Int)  // milliseconds
    case failed
    case insecure
}
