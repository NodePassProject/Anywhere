//
//  Debouncer.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
final class Debouncer {
    private let interval: Duration
    private var task: Task<Void, Never>?

    init(interval: Duration) {
        self.interval = interval
    }

    func schedule(_ work: @escaping @MainActor () async -> Void) {
        let previous = task
        previous?.cancel()
        task = Task {
            try? await Task.sleep(for: interval)
            guard !Task.isCancelled else { return }
            await previous?.value
            guard !Task.isCancelled else { return }
            await work()
        }
    }
}
