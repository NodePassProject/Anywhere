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

    private final class Source: DeadlineSource {
        private struct Span {
            var label = ""
            var deadline: Deadline?
        }
        private let span = Mutex(Span())

        func begin(_ label: String) {
            let deadline = Deadline(in: .seconds(MITMScriptWatchdog.hardCapSeconds), precision: .lazy)
            span.withLock { span in
                span.label = label
                span.deadline = deadline
            }
        }

        func end() {
            span.withLock { span in
                span.label = ""
                span.deadline = nil
            }
        }

        func nextDeadline() -> Deadline? {
            span.withLock { $0.deadline }
        }

        func fire(now: MonotonicClock.Instant) {
            let label: String? = span.withLock { span in
                guard let deadline = span.deadline, deadline.scheduledAt <= now else { return nil }
                return span.label
            }
            guard let label else { return }
            let shown = label.count > 200 ? String(label.prefix(200)) + "…" : label
            MITMScriptDiskStore.shared.flush()
            fatalError("A JavaScript script span ran \(MITMScriptWatchdog.hardCapSeconds)s without returning. Offending script: \(shown)")
        }
    }

    private static let source = Source()
    private static let registration = TickScheduler.shared.register(source)

    static func begin(_ label: String) {
        source.begin(label)
        registration.poke()
    }

    static func end() {
        source.end()
    }
}
