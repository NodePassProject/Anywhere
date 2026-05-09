//
//  LatencyResult.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/9/26.
//

import Foundation

enum LatencyResult: Sendable {
    case testing
    case success(Int)  // milliseconds
    case failed
    case insecure
}
