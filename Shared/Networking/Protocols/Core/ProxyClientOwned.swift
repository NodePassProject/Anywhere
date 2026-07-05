//
//  ProxyClientOwned.swift
//  Anywhere
//
//  Created by NodePassProject on 7/5/26.
//

import Foundation

// MARK: - ProxyClientOwned

protocol ProxyClientOwned: AnyObject {
    func releaseOwned()
}

protocol AwaitableProxyClientOwned: ProxyClientOwned {
    func releaseOwned(completion: @escaping @Sendable () -> Void)
}

// MARK: - Transports

extension NWTCPTransport: AwaitableProxyClientOwned {
    func releaseOwned() { forceCancel() }
    func releaseOwned(completion: @escaping @Sendable () -> Void) { forceCancel(completion: completion) }
}

extension NWUDPTransport: ProxyClientOwned {
    func releaseOwned() { cancel() }
}

// MARK: - Security layers

extension TLSClient: ProxyClientOwned {
    func releaseOwned() { cancel() }
}

extension RealityClient: ProxyClientOwned {
    func releaseOwned() { cancel() }
}

extension TLSRecordConnection: ProxyClientOwned {
    func releaseOwned() { cancel() }
}

// MARK: - Transport wrappers

extension WebSocketConnection: ProxyClientOwned {
    func releaseOwned() { cancel() }
}

extension HTTPUpgradeConnection: ProxyClientOwned {
    func releaseOwned() { cancel() }
}

extension GRPCConnection: ProxyClientOwned {
    func releaseOwned() { cancel() }
}

extension XHTTPConnection: ProxyClientOwned {
    func releaseOwned() { cancel() }
}

// MARK: - Connections and per-flow sessions

extension ProxyConnection: ProxyClientOwned {
    func releaseOwned() { cancel() }
}

extension NaiveTunnelAdapter: ProxyClientOwned {
    func releaseOwned() { close() }
}

extension NaiveHTTP3Stream: ProxyClientOwned {
    func releaseOwned() { close() }
}

extension SudokuConnectionFactory: ProxyClientOwned {
    func releaseOwned() { closeAll() }
}

// MARK: - Chain hops

extension ProxyClient: AwaitableProxyClientOwned {
    func releaseOwned() { cancel() }
    func releaseOwned(completion: @escaping @Sendable () -> Void) { cancel(completion: completion) }
}
