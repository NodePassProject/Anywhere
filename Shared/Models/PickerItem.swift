//
//  PickerItem.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

struct PickerItem: Identifiable, Hashable {
    let id: UUID
    let name: String
}

struct PickerSection: Identifiable {
    let id: UUID
    /// Header text, or `nil` for an ungrouped section (chains, standalone configs).
    let header: String?
    let items: [PickerItem]
}
