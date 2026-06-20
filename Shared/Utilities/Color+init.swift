//
//  Color+init.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

extension Color {
    init(hex: UInt, alpha: Double = 1) {
        self.init(
            .sRGB,
            red:   Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue:  Double(hex & 0xFF) / 255,
            opacity: alpha
        )
    }

    #if canImport(UIKit)
    var archivedData: Data? {
        try? NSKeyedArchiver.archivedData(withRootObject: UIColor(self), requiringSecureCoding: true)
    }
    
    init?(archivedData data: Data) {
        guard let uiColor = try? NSKeyedUnarchiver.unarchivedObject(ofClass: UIColor.self, from: data) else {
            return nil
        }
        self.init(uiColor: uiColor)
    }
    #endif
}
