//
//  AppState.swift
//  Anywhere
//
//  Created by NodePassProject on 8/3/26.
//

import Foundation
import Observation

@MainActor
@Observable
final class AppState {
    var orphanedRuleSetNames: [String] = []
}
