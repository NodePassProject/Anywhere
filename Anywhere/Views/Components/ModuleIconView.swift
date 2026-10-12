//
//  ModuleIconView.swift
//  Anywhere
//
//  Created by NodePassProject on 10/9/26.
//

import SwiftUI

struct ModuleIconView: View {
    @Environment(\.colorScheme) private var colorScheme
    
    let iconLight: Data?
    let iconDark: Data?
    var size: CGFloat = 30
    var cornerRadius: CGFloat = 8

    private var iconData: Data? {
        switch colorScheme {
        case .dark: iconDark ?? iconLight
        default: iconLight ?? iconDark
        }
    }

    var body: some View {
        if let icon = iconData, let image = UIImage(data: icon) {
            Image(uiImage: image)
                .interpolation(.high)
                .resizable()
                .scaledToFit()
                .frame(width: size, height: size)
                .clipShape(.rect(cornerRadius: cornerRadius))
        } else {
            Image(systemName: "shippingbox")
                .foregroundStyle(.secondary)
                .frame(width: size, height: size)
        }
    }
}
