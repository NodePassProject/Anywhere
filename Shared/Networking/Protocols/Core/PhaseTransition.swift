//
//  PhaseTransition.swift
//  Anywhere
//
//  Created by NodePassProject on 8/14/26.
//

import Foundation

nonisolated protocol PhaseTransitionable {
    static func canTransition(from old: Self, to new: Self) -> Bool
}

nonisolated extension PhaseTransitionable {
    @discardableResult
    static func transition(_ phase: inout Self, to new: Self) -> Bool {
        guard canTransition(from: phase, to: new) else { return false }
        phase = new
        return true
    }
}

nonisolated protocol PhaseHolding {
    associatedtype Phase: PhaseTransitionable
    var phase: Phase { get set }
}

nonisolated extension PhaseHolding {
    @discardableResult
    mutating func transition(to new: Phase) -> Bool {
        Phase.transition(&phase, to: new)
    }
}
