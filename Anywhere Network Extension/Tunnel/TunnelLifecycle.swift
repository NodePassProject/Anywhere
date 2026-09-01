//
//  TunnelLifecycle.swift
//  Anywhere
//
//  Created by NodePassProject on 8/13/26.
//

import Synchronization

nonisolated enum TunnelPhase: UInt8, AtomicRepresentable, CustomStringConvertible, PhaseTransitionable {
    case idle
    case starting
    case running
    case suspended
    case stopping
    case stopped

    static func canTransition(from old: TunnelPhase, to new: TunnelPhase) -> Bool {
        switch (old, new) {
        case (.idle, .starting),
             (.stopped, .starting),
             (.starting, .running),
             (.running, .suspended),
             (.suspended, .running),
             (.starting, .stopping),
             (.running, .stopping),
             (.suspended, .stopping),
             (.stopping, .stopped):
            return true
        default:
            return false
        }
    }

    var isActive: Bool { self == .running || self == .suspended }

    var description: String {
        switch self {
        case .idle: "idle"
        case .starting: "starting"
        case .running: "running"
        case .suspended: "suspended"
        case .stopping: "stopping"
        case .stopped: "stopped"
        }
    }
}

nonisolated enum LwipAbortContext: UInt8, AtomicRepresentable {
    case none
    case teardown
}
