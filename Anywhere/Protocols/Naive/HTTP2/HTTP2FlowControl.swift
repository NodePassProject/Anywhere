//
//  HTTP2FlowControl.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/9/26.
//

import Foundation

/// Tracks HTTP/2 send and receive flow-control windows for a single connection + stream.
///
/// Window sizing matches NaiveProxy's bandwidth-delay product calculation:
/// - `kMaxBandwidthMBps = 125`, `kTypicalRttSecond = 0.256`
/// - `kMaxBdpMB = 32 MB`, `kTypicalWindow = 64 MB` (2× BDP)
/// - Session max receive window = 128 MB (2× stream window)
struct HTTP2FlowControl {
    /// HTTP/2 default initial window size (RFC 7540 §6.9.2).
    static let defaultInitialWindowSize = 65_535
    /// NaiveProxy's stream initial window size (64 MB).
    static let naiveInitialWindowSize = 67_108_864
    /// NaiveProxy's session (connection) max receive window (128 MB).
    static let naiveSessionMaxRecvWindow = 134_217_728

    /// WINDOW_UPDATE increment to send on stream 0 after SETTINGS exchange.
    /// Expands connection receive window from 65,535 to 128 MB.
    static let connectionWindowUpdateIncrement = UInt32(naiveSessionMaxRecvWindow - defaultInitialWindowSize)

    // MARK: - Send Windows (limited by remote peer's settings)

    /// How many bytes we can send on the connection.
    private(set) var connectionSendWindow: Int = defaultInitialWindowSize
    /// How many bytes we can send on stream 1.
    private(set) var streamSendWindow: Int = defaultInitialWindowSize

    // MARK: - Receive Windows (limited by our settings)

    /// Bytes received but not yet acknowledged via WINDOW_UPDATE (connection level).
    private var connectionRecvConsumed: Int = 0
    /// Bytes received but not yet acknowledged via WINDOW_UPDATE (stream level).
    private var streamRecvConsumed: Int = 0

    /// The receive window size we advertised for streams.
    private var streamRecvWindowSize: Int = Self.naiveInitialWindowSize
    /// The receive window size for the connection (after our WINDOW_UPDATE).
    private var connectionRecvWindowSize: Int = Self.naiveSessionMaxRecvWindow

    // MARK: - Send

    /// Checks if we can send `bytes` and consumes from both connection and stream send windows.
    ///
    /// Returns `true` if the send is allowed; `false` if it would exceed a window.
    mutating func consumeSendWindow(bytes: Int) -> Bool {
        guard connectionSendWindow >= bytes && streamSendWindow >= bytes else { return false }
        connectionSendWindow -= bytes
        streamSendWindow -= bytes
        return true
    }

    /// Returns the maximum number of bytes we can send right now.
    var maxSendBytes: Int { min(connectionSendWindow, streamSendWindow) }

    // MARK: - Receive

    /// Records that `bytes` of DATA have been received.
    ///
    /// Returns WINDOW_UPDATE increments to send: `(connectionIncrement, streamIncrement)`.
    /// Either may be `nil` if no update is needed yet.
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

    /// Applies a WINDOW_UPDATE received from the server.
    mutating func applyWindowUpdate(streamID: UInt32, increment: Int) {
        if streamID == 0 {
            connectionSendWindow += increment
        } else {
            streamSendWindow += increment
        }
    }

    /// Applies the server's SETTINGS_INITIAL_WINDOW_SIZE.
    ///
    /// Adjusts our stream send window by the difference between the new and old values
    /// (RFC 7540 §6.9.2).
    mutating func applySettings(initialWindowSize: Int) {
        let delta = initialWindowSize - Self.defaultInitialWindowSize
        streamSendWindow += delta
    }
}
