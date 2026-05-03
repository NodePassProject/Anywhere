//
//  MITMStore.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import Foundation
import Combine
import SwiftUI

@MainActor
final class MITMStore: ObservableObject {
    static let shared = MITMStore()

    @Published var enabled: Bool {
        didSet {
            guard enabled != oldValue else { return }
            save()
        }
    }

    @Published private(set) var rules: [MITMRule]

    private init() {
        let snapshot = MITMSnapshot.load()
        self.enabled = snapshot.enabled
        self.rules = snapshot.rules
    }

    // MARK: - Mutations

    func add(_ rule: MITMRule) {
        rules.append(rule)
        save()
    }

    func update(_ rule: MITMRule) {
        guard let index = rules.firstIndex(where: { $0.id == rule.id }) else { return }
        rules[index] = rule
        save()
    }

    func remove(atOffsets offsets: IndexSet) {
        rules.remove(atOffsets: offsets)
        save()
    }

    func remove(id: UUID) {
        rules.removeAll { $0.id == id }
        save()
    }

    func move(fromOffsets source: IndexSet, toOffset destination: Int) {
        rules.move(fromOffsets: source, toOffset: destination)
        save()
    }

    // MARK: - Persistence

    private func save() {
        MITMSnapshot(enabled: enabled, rules: rules).save()
    }
}
