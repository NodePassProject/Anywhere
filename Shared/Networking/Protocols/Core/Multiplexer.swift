//
//  Multiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 6/15/26.
//

import Foundation

// MARK: - Multiplexer

nonisolated protocol Multiplexer: AnyObject {
    /// Closed multiplexers are evicted by their pool.
    var isClosed: Bool { get }

    var activeStreamCount: Int { get }

    /// `error` non-nil for transport failure, nil for clean close.
    func close(error: Error?)
}

// MARK: - MultiplexerStreamSink

protocol MultiplexerStreamSink: AnyObject {
    nonisolated func deliverData(_ data: Data)

    /// `error` non-nil for abnormal termination, nil for clean EOF.
    nonisolated func deliverClose(error: Error?)
}
