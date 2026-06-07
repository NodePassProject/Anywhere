//
//  MetricTimer.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import Foundation

/// The standard stopwatch for connection-establishment latencies: time a span,
/// then record it to ``ConnectionMetrics`` on ``stop()``. Reusable for any
/// ``ConnectionMetrics/Metric`` — dial, handshake, and future timings — so owners
/// don't re-implement start/stop/record and the socket/proxy primitives stay free
/// of metrics logic.
///
/// Two usage styles:
/// - ``start()`` / ``stop()`` when the owner controls both timing points (e.g.
///   the dial: `start()` after DNS, `stop()` once connected).
/// - ``timing(_:_:)`` to wrap a single `Result` completion handler (e.g. the
///   proxy handshake, and any future callback-based step).
///
/// A value type: no per-use allocation. Each owner keeps its own and drives it
/// from a single queue.
nonisolated struct MetricTimer {
    let metric: ConnectionMetrics.Metric
    /// Whether ``stop()`` records. Set `false` to measure-but-not-record — e.g.
    /// direct/bypass dials, which aren't proxied connections.
    var enabled = true
    private var startedAt: ContinuousClock.Instant?

    init(_ metric: ConnectionMetrics.Metric) {
        self.metric = metric
    }

    /// Begins (or restarts) timing. For the dial, call after DNS so resolution
    /// time is excluded from the measured latency.
    mutating func start() {
        startedAt = ContinuousClock().now
    }

    /// Records the elapsed span to ``ConnectionMetrics``. No-op if disabled or
    /// never started, so it's safe to leave uncalled (e.g. on a failed connect).
    func stop() {
        guard enabled, let startedAt else { return }
        ConnectionMetrics.shared.record(metric, ContinuousClock().now - startedAt)
    }

    /// Times a callback-based step: starts a timer for `metric` and returns a
    /// completion wrapper that records the elapsed span on `.success`, then
    /// forwards to `completion`. Failures forward untouched (the timer is simply
    /// never stopped). The standard way to time an async (completion-handler)
    /// operation without hand-writing a wrapper.
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
