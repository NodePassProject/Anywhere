//
//  Multiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 6/15/26.
//

import Foundation

// MARK: - Multiplexer

/// Common contract shared by every stream-fanout multiplexer (mux.cool, AnyTLS, HTTP/2, HTTP/3).
/// Each multiplexer owns one underlying connection and fans out many logical streams over it.
protocol Multiplexer: AnyObject {
    /// Whether the multiplexer has been torn down; closed multiplexers are evicted by their pool.
    var isClosed: Bool { get }

    /// Number of logical streams currently open on this multiplexer.
    var activeStreamCount: Int { get }

    /// Tears down the multiplexer and all its streams. `error` is non-nil for a transport failure,
    /// nil for a clean / deliberate close.
    func close(error: Error?)
}

// MARK: - MultiplexerStreamSink

/// The demux side of one logical stream: the owning multiplexer pushes inbound payload and
/// close / EOF notifications here as it parses the wire.
protocol MultiplexerStreamSink: AnyObject {
    /// Deliver inbound payload bytes to the stream.
    func deliverData(_ data: Data)

    /// Signal stream end. `error` is non-nil for an abnormal termination, nil for clean EOF.
    func deliverClose(error: Error?)
}
