//
//  Array+moveSubsequence.swift
//  Anywhere
//
//  Created by NodePassProject on 8/8/26.
//

import Foundation
import SwiftUI

nonisolated extension Array {
    mutating func moveSubsequence(where isIncluded: (Element) -> Bool, fromOffsets source: IndexSet, toOffset destination: Int) {
        let includedIndices = indices.filter { isIncluded(self[$0]) }
        var subset = includedIndices.map { self[$0] }
        subset.move(fromOffsets: source, toOffset: destination)
        for (offset, index) in includedIndices.enumerated() {
            self[index] = subset[offset]
        }
    }
}
