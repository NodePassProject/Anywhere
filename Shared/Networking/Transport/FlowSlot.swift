//
//  FlowSlot.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "FlowSlot")

// MARK: - FlowSlot

/// A release-once RAII handle over ``FlowGauge``: one live outbound socket.
///
/// Creating a slot increments the gauge; ``release()`` decrements it exactly once.
/// If a slot is deallocated without a `release()`, `deinit` recovers the count and
/// logs the regression.
nonisolated final class FlowSlot: @unchecked Sendable {

    enum Kind { case tcp, udp }

    private let kind: Kind
    /// Diagnostic context for the deinit-recovery log (e.g. "[TCP] host:port").
    private let context: String
    private let released = Atomic<Bool>(false)

    init(_ kind: Kind, context: String) {
        self.kind = kind
        self.context = context
        increment()
    }

    /// Decrements the gauge exactly once; subsequent calls (and `deinit`) no-op.
    func release() {
        guard claim() else { return }
        decrement()
    }

    deinit {
        guard claim() else { return }
        decrement()
        logger.error("\(context) released its flow slot in deinit — teardown never ran; FlowGauge count recovered. A cancel path has regressed.")
    }

    /// Wins the single decrement, or returns false if it's already been taken.
    private func claim() -> Bool {
        released.compareExchange(expected: false, desired: true, ordering: .relaxed).exchanged
    }

    private func increment() {
        switch kind {
        case .tcp: FlowGauge.incrementTCP()
        case .udp: FlowGauge.incrementUDP()
        }
    }

    private func decrement() {
        switch kind {
        case .tcp: FlowGauge.decrementTCP()
        case .udp: FlowGauge.decrementUDP()
        }
    }
}
