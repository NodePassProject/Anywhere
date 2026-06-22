//
//  TLSProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

nonisolated class TLSProxyConnection: ProxyConnection {
    private let tlsConnection: TLSRecordConnection

    init(tlsConnection: TLSRecordConnection) {
        self.tlsConnection = tlsConnection
    }

    override var outerTLSVersion: TLSVersion? { TLSVersion(rawValue: tlsConnection.tlsVersion) }

    override var isConnected: Bool {
        tlsConnection.connection?.isTransportReady ?? false
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        tlsConnection.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        tlsConnection.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        tlsConnection.receive(completion: completion)
    }

    override func cancel() {
        tlsConnection.cancel()
    }

    override func receiveDirectRaw(completion: @escaping (Data?, Error?) -> Void) {
        tlsConnection.receiveRaw(completion: completion)
    }

    override func sendDirectRaw(data: Data, completion: @escaping (Error?) -> Void) {
        tlsConnection.sendRaw(data: data, completion: completion)
    }

    override func sendDirectRaw(data: Data) {
        tlsConnection.sendRaw(data: data)
    }
}
