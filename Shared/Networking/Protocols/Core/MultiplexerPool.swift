//
//  MultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 4/14/26.
//

import Foundation

// MARK: - MultiplexerPool

/// Generic base for pooled-multiplexer managers keyed by `host:port:sni`.
/// The pooled type conforms to ``Multiplexer`` (see Multiplexer.swift).
nonisolated class MultiplexerPool<S: Multiplexer> {

    /// Guards `multiplexers` and any subclass-owned auxiliary storage.
    let lock = UnfairLock()

    var multiplexers: [String: [S]] = [:]

    init() {}

    static func makeKey(host: String, port: UInt16, sni: String) -> String {
        "\(host):\(port):\(sni)"
    }

    func removeMultiplexer(_ multiplexer: S, key: String) {
        lock.lock()
        multiplexers[key]?.removeAll { $0 === multiplexer }
        if multiplexers[key]?.isEmpty == true {
            multiplexers.removeValue(forKey: key)
        }
        lock.unlock()
    }

    /// Closes every pooled multiplexer; subclasses override to also cover auxiliary storage they own.
    func closeAll() {
        lock.lock()
        let all = multiplexers.values.flatMap { $0 }
        multiplexers.removeAll()
        lock.unlock()

        for multiplexer in all {
            multiplexer.close(error: nil)
        }
    }
}

extension MultiplexerPool: TransportPool {
    func reclaim() { closeAll() }
}
