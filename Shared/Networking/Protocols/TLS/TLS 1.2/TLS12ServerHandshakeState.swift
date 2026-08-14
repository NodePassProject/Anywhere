//
//  TLS12ServerHandshakeState.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation

nonisolated struct TLS12ServerHandshakeState {
    enum Flight: PhaseTransitionable {
        case awaitingClientKeyExchange
        case awaitingChangeCipherSpec
        case awaitingFinished

        static func canTransition(from old: Flight, to new: Flight) -> Bool {
            switch (old, new) {
            case (.awaitingClientKeyExchange, .awaitingChangeCipherSpec),
                 (.awaitingChangeCipherSpec, .awaitingFinished):
                return true
            default:
                return false
            }
        }
    }
    var flight: Flight = .awaitingClientKeyExchange

    var ccsBudget = 4

    var transcript: Data = Data()
    var masterSecret: Data?
    var keys: TLS12HandshakeKeys?
    var clientRandom: Data?
    var serverRandom: Data?
    var extendedMasterSecret: Bool = false
}
