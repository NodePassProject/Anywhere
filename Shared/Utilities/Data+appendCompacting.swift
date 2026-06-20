//
//  Data+appendCompacting.swift
//  Anywhere
//
//  Created by NodePassProject on 6/12/26.
//

import Foundation

extension Data {
    /// `other` must be a freshly allocated read: when `self` is empty it is
    /// adopted as-is, slices and all.
    mutating func appendCompacting(_ other: Data) {
        if isEmpty {
            self = other
            return
        }
        var fresh = Data(capacity: count + other.count)
        fresh.append(self)
        fresh.append(other)
        self = fresh
    }
}
