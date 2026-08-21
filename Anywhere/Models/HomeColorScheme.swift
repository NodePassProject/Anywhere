//
//  HomeColorScheme.swift
//  Anywhere
//
//  Created by NodePassProject on 6/20/26.
//

import Foundation
import SwiftUI

enum HomeColorScheme: String, CaseIterable {
    case dark
    case light
    
    var colorScheme: ColorScheme {
        switch self {
        case .dark: .dark
        case .light: .light
        }
    }
}
