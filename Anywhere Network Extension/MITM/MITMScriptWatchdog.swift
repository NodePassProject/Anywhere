//
//  MITMScriptWatchdog.swift
//  Anywhere
//
//  Created by NodePassProject on 6/3/26.
//

import Foundation
import Synchronization

nonisolated enum MITMScriptWatchdog {
    static let hardCapSeconds = 30

    private struct Span {
        var generation: UInt64 = 0
        var label = ""
        var deadline: DeadlineToken?
    }
    private static let span = Mutex(Span())

    static func begin(_ label: String) {
        let stale: DeadlineToken? = span.withLock { span in
            let previous = span.deadline
            span.generation &+= 1
            span.label = label
            let generation = span.generation
            span.deadline = TickScheduler.shared.schedule(in: .seconds(hardCapSeconds), precision: .lazy) {
                checkInFlightSpan(generation: generation)
            }
            return previous
        }
        stale?.cancel()
    }

    static func end() {
        let armed: DeadlineToken? = span.withLock { span in
            let armed = span.deadline
            span.deadline = nil
            span.label = ""
            return armed
        }
        armed?.cancel()
    }

    private static func checkInFlightSpan(generation: UInt64) {
        let label: String? = span.withLock { span in
            guard span.deadline != nil, span.generation == generation else { return nil }
            return span.label
        }
        guard let label else { return }
        let shown = label.count > 200 ? String(label.prefix(200)) + "…" : label
        fatalError("A JavaScript script span ran \(hardCapSeconds)s without returning. Offending script: \(shown)")
    }
}
