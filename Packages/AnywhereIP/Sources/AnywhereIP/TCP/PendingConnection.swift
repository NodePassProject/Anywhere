//
//  PendingConnection.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

public struct PendingConnection: Sendable {
    private let stream: Stream
    public var source: IPEndpoint { stream.source }
    public var destination: IPEndpoint { stream.destination }
    init(stream: Stream) { self.stream = stream }
    public func accept() -> Stream? { stream.resolve(.accept) ? stream : nil }
    public func reject(reset: Bool = true) { _ = stream.resolve(reset ? .reset : .drop) }
}
