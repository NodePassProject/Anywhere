//
//  HTTPTunnel.swift
//  Anywhere
//
//  Created by NodePassProject on 6/2/26.
//

import Foundation

// MARK: - HTTPTunnel

/// Generic contract for an HTTP CONNECT tunnel (HTTP/1.1, HTTP/2, …).
protocol HTTPTunnel: AnyObject {

    var isConnected: Bool { get }

    /// CONNECT response headers, populated once `openTunnel` succeeds; empty
    /// for tunnels that don't expose headers (e.g. HTTP/1.1).
    var responseHeaders: [(name: String, value: String)] { get }

    func openTunnel(completion: @escaping (Error?) -> Void)

    func sendData(_ data: Data, completion: @escaping (Error?) -> Void)

    /// `nil` data signals EOF.
    func receiveData(completion: @escaping (Data?, Error?) -> Void)

    func close()
}
