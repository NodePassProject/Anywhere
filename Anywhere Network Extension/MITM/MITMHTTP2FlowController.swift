//
//  MITMHTTP2FlowController.swift
//  Anywhere
//
//  Created by NodePassProject on 6/2/26.
//

import Synchronization

nonisolated final class MITMHTTP2FlowController: Sendable {
    
    static let maxWindow = 0x7FFF_FFFF

    private struct Windows {
        var connection = 65_535
        var clientInitialStream = 65_535
        var serverConnection = 65_535
        var serverInitialStream = 65_535
    }

    private let windows = Mutex(Windows())
    
    var connectionWindow: Int { windows.withLock { $0.connection } }
    var clientInitialStreamWindow: Int { windows.withLock { $0.clientInitialStream } }
    var serverConnectionWindow: Int { windows.withLock { $0.serverConnection } }
    var serverInitialStreamWindow: Int { windows.withLock { $0.serverInitialStream } }
    
    func takeConnection(upTo requested: Int) -> Int {
        windows.withLock { w in
            let grant = max(0, min(w.connection, requested))
            w.connection -= grant
            return grant
        }
    }
    
    func creditConnection(_ increment: Int) {
        windows.withLock { $0.connection = min(Self.maxWindow, $0.connection &+ increment) }
    }
    
    func takeServerConnection(upTo requested: Int) -> Int {
        windows.withLock { w in
            let grant = max(0, min(w.serverConnection, requested))
            w.serverConnection -= grant
            return grant
        }
    }
    
    func creditServerConnection(_ increment: Int) {
        windows.withLock { $0.serverConnection = min(Self.maxWindow, $0.serverConnection &+ increment) }
    }
    
    func updateInitialStreamWindow(_ newValue: Int) -> Int {
        windows.withLock { w in
            // RFC 9113 §6.5.2: values above 2^31-1 are a FLOW_CONTROL_ERROR; clamp our model too.
            let clamped = min(newValue, Self.maxWindow)
            let delta = clamped - w.clientInitialStream
            w.clientInitialStream = clamped
            return delta
        }
    }
    
    func updateServerInitialStreamWindow(_ newValue: Int) -> Int {
        windows.withLock { w in
            let clamped = min(newValue, Self.maxWindow)
            let delta = clamped - w.serverInitialStream
            w.serverInitialStream = clamped
            return delta
        }
    }
}
