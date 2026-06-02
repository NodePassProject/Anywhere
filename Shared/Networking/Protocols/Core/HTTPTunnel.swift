//
//  HTTPTunnel.swift
//  Anywhere
//
//  Created by NodePassProject on 6/2/26.
//

import Foundation

// MARK: - HTTPTunnel

/// A transport-neutral HTTP CONNECT tunnel (HTTP/1.1, HTTP/2, …).
///
/// This is the generic contract every HTTP-version tunnel implements. It knows
/// nothing about any specific proxy protocol — credentials, User-Agent, padding
/// and other request decorations are supplied by the caller as
/// ``extraConnectHeaders`` closures, and the negotiated CONNECT response headers
/// are exposed via ``responseHeaders`` so a proxy layer (e.g. NaiveProxy's
/// padding negotiation) can interpret them after the tunnel opens.
///
/// NaiveProxy adapts these tunnels to its own `NaiveTunnel` via
/// ``NaiveTunnelAdapter``, layering padding negotiation on top.
protocol HTTPTunnel: AnyObject {

    /// Whether the tunnel is open and ready for data transfer.
    var isConnected: Bool { get }

    /// The CONNECT response headers, populated once ``openTunnel(completion:)``
    /// completes successfully. Empty for tunnels that don't expose headers
    /// (e.g. HTTP/1.1, which only parses a status line).
    var responseHeaders: [(name: String, value: String)] { get }

    /// Establishes the tunnel (transport connect + protocol handshake + CONNECT).
    func openTunnel(completion: @escaping (Error?) -> Void)

    /// Sends data through the established tunnel.
    func sendData(_ data: Data, completion: @escaping (Error?) -> Void)

    /// Receives the next chunk of data, `nil` data for EOF, or an error.
    func receiveData(completion: @escaping (Data?, Error?) -> Void)

    /// Closes the tunnel and releases its transport.
    func close()
}
