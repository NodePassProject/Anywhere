//
//  DialDeadline.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation
import Synchronization

protocol DialDeadlineDelegate: AnyObject, Sendable {
    nonisolated func dialDeadlineDidExpire()
}

nonisolated final class DialDeadline: Sendable {
    private struct WeakDelegate: Sendable { weak var value: (any DialDeadlineDelegate)? }

    private let duration: Duration
    private let delegate: WeakDelegate
    private let task = Mutex<Task<Void, Never>?>(nil)

    init(_ duration: Duration, delegate: any DialDeadlineDelegate) {
        self.duration = duration
        self.delegate = WeakDelegate(value: delegate)
    }
    
    func arm() {
        let delegate = self.delegate.value
        let fresh = Task {
            do { try await Task.sleep(for: duration) } catch { return }
            guard !Task.isCancelled else { return }
            delegate?.dialDeadlineDidExpire()
        }
        task.withLock { existing in
            existing?.cancel()
            existing = fresh
        }
    }
    
    func disarm() {
        task.withLock { existing in
            existing?.cancel()
            existing = nil
        }
    }

    deinit {
        task.withLock { $0?.cancel() }
    }
}
