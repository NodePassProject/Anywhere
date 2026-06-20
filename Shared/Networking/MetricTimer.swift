//
//  MetricTimer.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import Foundation

/// Not thread-safe; each owner drives its own instance from a single queue.
nonisolated struct MetricTimer {
    let metric: ConnectionMetrics.Metric
    /// When `false`, ``stop()`` skips recording — e.g. direct/bypass dials.
    var enabled = true
    private var startedAt: ContinuousClock.Instant?

    init(_ metric: ConnectionMetrics.Metric) {
        self.metric = metric
    }

    /// Begins (or restarts) timing; for dials, call after DNS so resolution is excluded.
    mutating func start() {
        startedAt = ContinuousClock().now
    }

    func stop() {
        guard enabled, let startedAt else { return }
        ConnectionMetrics.shared.record(metric, ContinuousClock().now - startedAt)
    }

    /// Records elapsed time only on `.success` before forwarding the result.
    static func timing<Value, Failure: Error>(
        _ metric: ConnectionMetrics.Metric,
        _ completion: @escaping (Result<Value, Failure>) -> Void
    ) -> (Result<Value, Failure>) -> Void {
        var timer = MetricTimer(metric)
        timer.start()
        return { [timer] result in
            if case .success = result { timer.stop() }
            completion(result)
        }
    }
}
