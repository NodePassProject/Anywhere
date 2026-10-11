//
//  ConnectionError.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

public enum ConnectionError: Error, Hashable, Sendable {
    case reset
    case aborted
    case closed
    case concurrentOperation
    case bufferLimit
}
