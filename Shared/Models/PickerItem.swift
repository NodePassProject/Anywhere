//
//  PickerItem.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

/// Picker Item used by VPNViewModel and the Home proxy picker.
struct PickerItem: Identifiable {
    let id: UUID
    let name: String
}
