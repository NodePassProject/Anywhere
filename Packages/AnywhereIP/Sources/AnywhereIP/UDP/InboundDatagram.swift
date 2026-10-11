//
//  InboundDatagram.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/25/26.
//

import Foundation

public struct InboundDatagram: Sendable {
    public let source: IPEndpoint
    public let destination: IPEndpoint
    public let payload: Data
    let packet: Data

    init(source: IPEndpoint, destination: IPEndpoint, payload: Data, packet: Data) {
        self.source = source
        self.destination = destination
        self.payload = payload
        self.packet = packet
    }
}
