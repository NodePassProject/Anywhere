//
//  FlowBufferLedger.swift
//  Anywhere
//
//  Created by NodePassProject on 8/30/26.
//

import Foundation
import Synchronization

typealias TCPBufferLedger = FlowBufferLedger<TCPConnection>
typealias UDPBufferLedger = FlowBufferLedger<TunnelStack.UDPFlowKey>

nonisolated final class FlowBufferLedger<Handle: Sendable>: Sendable {
    struct Victim: Sendable {
        let id: ObjectIdentifier
        let handle: Handle
        let bytes: Int
    }

    enum Admission {
        case admitted(evicting: [Victim])
        case selfEvicted(alsoEvicting: [Victim])
        case dropped
    }

    private struct Entry {
        let handle: Handle
        var bytes: Int
    }

    private struct State {
        var entries: [ObjectIdentifier: Entry] = [:]
        var evicted: Set<ObjectIdentifier> = []
        var total = 0
    }

    private let state = Mutex(State())
    private let budget: Int

    init(budget: Int) {
        self.budget = budget
    }

    var totalBytes: Int { state.withLock { $0.total } }
    
    // MARK: - Absolute-sync admission (TCP)
    
    func set(
        flow id: ObjectIdentifier,
        handle: Handle,
        bytes: Int
    ) -> [Victim] {
        state.withLock { state in
            guard !state.evicted.contains(id) else { return [] }
            
            let old = state.entries[id]?.bytes ?? 0
            state.entries[id, default: Entry(handle: handle, bytes: 0)].bytes = bytes
            state.total += bytes - old
            
            var victims: [Victim] = []
            while state.total > budget {
                guard let victim = evictLargest(&state) else { break }
                victims.append(victim)
            }
            return victims
        }
    }

    // MARK: - Reserve/release admission (UDP)
    
    func reserve(
        flow id: ObjectIdentifier,
        handle: Handle,
        bytes: Int
    ) -> Admission {
        state.withLock { state in
            guard !state.evicted.contains(id), bytes <= budget else { return .dropped }
            
            var victims: [Victim] = []
            while state.total + bytes > budget {
                guard let victim = evictLargest(&state) else { break }
                if victim.id == id {
                    return .selfEvicted(alsoEvicting: victims)
                }
                victims.append(victim)
            }
            
            state.entries[id, default: Entry(handle: handle, bytes: 0)].bytes += bytes
            state.total += bytes
            return .admitted(evicting: victims)
        }
    }
    
    func release(flow id: ObjectIdentifier, bytes: Int) {
        state.withLock { st in
            guard var entry = st.entries[id] else { return }
            let freed = min(entry.bytes, bytes)
            entry.bytes -= freed
            st.entries[id] = entry
            st.total -= freed
        }
    }

    // MARK: - Teardown
    
    func releaseAll(flow id: ObjectIdentifier) {
        state.withLock { state in
            if let entry = state.entries.removeValue(forKey: id) {
                state.total -= entry.bytes
            }
            state.evicted.remove(id)
        }
    }

    // MARK: - Eviction core

    private func evictLargest(_ state: inout State) -> Victim? {
        guard let (victimID, entry) = state.entries.max(by: { $0.value.bytes < $1.value.bytes }),
              entry.bytes > 0 else { return nil }
        state.entries.removeValue(forKey: victimID)
        state.evicted.insert(victimID)
        state.total -= entry.bytes
        return Victim(id: victimID, handle: entry.handle, bytes: entry.bytes)
    }
}
