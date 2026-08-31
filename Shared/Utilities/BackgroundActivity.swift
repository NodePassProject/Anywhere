//
//  BackgroundActivity.swift
//  Anywhere
//
//  Created by NodePassProject on 9/1/26.
//

import Foundation

nonisolated final class BackgroundActivity: Sendable {
    private let release = DispatchSemaphore(value: 0)

    init(reason: String) {
        ProcessInfo.processInfo.performExpiringActivity(withReason: reason) { [release] expired in
            guard !expired else { return }
            release.wait()
        }
    }

    func end() {
        release.signal()
    }
}
