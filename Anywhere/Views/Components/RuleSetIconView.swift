//
//  RuleSetIconView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/18/26.
//

import SwiftUI

struct RuleSetIconView: View {
    let iconLight: Data?
    let iconDark: Data?

    @Environment(\.colorScheme) private var colorScheme

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
                .frame(width: 32, height: 32)
                .clipShape(.rect(cornerRadius: 7))
                .overlay(
                    RoundedRectangle(cornerRadius: 7)
                        .strokeBorder(.gray.opacity(0.2), lineWidth: 1)
                )
        } else {
            Image(systemName: "list.bullet.rectangle")
                .foregroundStyle(.secondary)
                .frame(width: 32, height: 32)
        }
    }
}
