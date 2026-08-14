//
//  NaiveHTTP2FlowControl.swift
//  Anywhere
//
//  Created by NodePassProject on 3/9/26.
//

import Foundation

nonisolated enum NaiveHTTP2FlowControl {
    /// HTTP/2 default initial window size (RFC 7540 §6.9.2).
    static let defaultInitialWindowSize = 65_535
    /// Per-stream initial receive window (64 MB), sized for high-BDP links.
    static let naiveInitialWindowSize = 67_108_864
    /// Connection (multiplexer) max receive window (128 MB).
    static let naiveSessionMaxReceiveWindow = 134_217_728

    /// WINDOW_UPDATE increment sent on stream 0 after SETTINGS, expanding the connection window to 128 MB.
    static let connectionWindowUpdateIncrement = UInt32(naiveSessionMaxReceiveWindow - defaultInitialWindowSize)
}
