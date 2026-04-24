//
//  SubscriptionDomainHelper.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/24/26.
//

class SubscriptionDomainHelper {
    static let domainsShouldDisableProxyEditing: [String] = ["sub.example.com", "sub.cdnjst.org"]
    static let domainsRequireRemnawaveHWID: [String] = ["sub.example.com", "sub.cdnjst.org"]
    
    static func shouldDisableProxyEditing(for url: String) -> Bool {
        for domain in domainsShouldDisableProxyEditing {
            if url.starts(with: "https://\(domain)/") {
                return true
            }
        }
        return false
    }
    
    static func shouldRequireRemnawaveHWID(for url: String) -> Bool {
        for domain in domainsRequireRemnawaveHWID {
            if url.starts(with: "https://\(domain)/") {
                return true
            }
        }
        return false
    }
}
