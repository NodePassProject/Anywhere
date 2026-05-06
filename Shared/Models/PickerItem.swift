//
//  PickerItem.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

/// Single picker entry — a chain or a configuration.
struct PickerItem: Identifiable, Hashable {
    let id: UUID
    let name: String
}

/// Group of picker items, optionally with a header (used for subscription groupings).
struct PickerSection: Identifiable {
    let id: UUID
    /// Header text, or `nil` for an ungrouped section (chains, standalone configs).
    let header: String?
    let items: [PickerItem]
}
