//
//  HTTPTunnel.swift
//  Anywhere
//
//  Created by NodePassProject on 6/2/26.
//

import Foundation

// MARK: - HTTPTunnel

protocol HTTPTunnel: AnyObject {

    var isConnected: Bool { get }

    /// CONNECT response headers, populated once `openTunnel` succeeds; empty
    /// for tunnels that don't expose headers (e.g. HTTP/1.1).
    var responseHeaders: [(name: String, value: String)] { get }

    func openTunnel() async throws

    func sendData(_ data: Data) async throws

    /// `nil` signals EOF.
    func receiveData() async throws -> Data?

    func close()
}
