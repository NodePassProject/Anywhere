//
//  HTTP2FlowControl.swift
//  Anywhere
//
//  Created by NodePassProject on 3/9/26.
//

import Foundation

/// HTTP/2 flow-control windows for one connection + stream, sized for high-BDP links:
/// 64 MB per stream (2× BDP at 125 MB/s / 256 ms RTT), 128 MB per connection.
struct HTTP2FlowControl {
    /// HTTP/2 default initial window size (RFC 7540 §6.9.2).
    static let defaultInitialWindowSize = 65_535
    /// Per-stream initial receive window (64 MB), sized for high-BDP links.
    static let naiveInitialWindowSize = 67_108_864
    /// Connection (session) max receive window (128 MB).
    static let naiveSessionMaxRecvWindow = 134_217_728

    /// WINDOW_UPDATE increment sent on stream 0 after SETTINGS, expanding the connection window to 128 MB.
    static let connectionWindowUpdateIncrement = UInt32(naiveSessionMaxRecvWindow - defaultInitialWindowSize)

    // MARK: - Send Windows (limited by remote peer's settings)

    private(set) var connectionSendWindow: Int = defaultInitialWindowSize
    private(set) var streamSendWindow: Int = defaultInitialWindowSize

    // MARK: - Receive Windows (limited by our settings)

    /// Bytes received but not yet acknowledged via WINDOW_UPDATE.
    private var connectionRecvConsumed: Int = 0
    private var streamRecvConsumed: Int = 0

    private var streamRecvWindowSize: Int = Self.naiveInitialWindowSize
    private var connectionRecvWindowSize: Int = Self.naiveSessionMaxRecvWindow

    // MARK: - Send

    /// Consumes `bytes` from both send windows. Returns `false` if either window is exhausted.
    mutating func consumeSendWindow(bytes: Int) -> Bool {
        guard connectionSendWindow >= bytes && streamSendWindow >= bytes else { return false }
        connectionSendWindow -= bytes
        streamSendWindow -= bytes
        return true
    }

    var maxSendBytes: Int { min(connectionSendWindow, streamSendWindow) }

    // MARK: - Receive

    /// Records received DATA bytes and returns any WINDOW_UPDATE increments to send.
    /// Either tuple element is `nil` if no update is needed yet.
    mutating func consumeRecvWindow(bytes: Int) -> (connectionIncrement: UInt32?, streamIncrement: UInt32?) {
        connectionRecvConsumed += bytes
        streamRecvConsumed += bytes

        var connInc: UInt32?
        var streamInc: UInt32?

        // Send WINDOW_UPDATE when >= 50% of window has been consumed
        if connectionRecvConsumed >= connectionRecvWindowSize / 2 {
            connInc = UInt32(connectionRecvConsumed)
            connectionRecvConsumed = 0
        }
        if streamRecvConsumed >= streamRecvWindowSize / 2 {
            streamInc = UInt32(streamRecvConsumed)
            streamRecvConsumed = 0
        }

        return (connInc, streamInc)
    }

    // MARK: - Remote Updates

    mutating func applyWindowUpdate(streamID: UInt32, increment: Int) {
        if streamID == 0 {
            connectionSendWindow += increment
        } else {
            streamSendWindow += increment
        }
    }

    /// Applies SETTINGS_INITIAL_WINDOW_SIZE by adjusting the stream send window by the delta (RFC 7540 §6.9.2).
    mutating func applySettings(initialWindowSize: Int) {
        let delta = initialWindowSize - Self.defaultInitialWindowSize
        streamSendWindow += delta
    }
}
