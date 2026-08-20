//
//  CertificateOperations.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
struct CertificateOperations {
    let store: CertificateStore

    @discardableResult
    func add(_ fingerprint: String) -> Bool {
        store.add(fingerprint)
    }

    func remove(_ fingerprint: String) {
        store.remove(fingerprint)
    }

    func remove(atOffsets offsets: IndexSet) {
        store.remove(atOffsets: offsets)
    }
}
