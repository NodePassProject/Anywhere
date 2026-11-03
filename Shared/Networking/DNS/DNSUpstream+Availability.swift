//
//  DNSUpstream+Availability.swift
//  Anywhere
//
//  Created by NodePassProject on 11/3/26.
//

import Foundation
import Synchronization

nonisolated extension DNSUpstream {
    private static let systemResolverUnavailableFlag = Atomic<Bool>(false)

    static var systemResolverUnavailable: Bool {
        get { systemResolverUnavailableFlag.load(ordering: .relaxed) }
        set { systemResolverUnavailableFlag.store(newValue, ordering: .relaxed) }
    }

    var reachable: DNSUpstream {
        guard isSystem, Self.systemResolverUnavailable else { return self }
        return AWCore.getFallbackDNSUpstream()
    }
}
