//
//  TextWithColorfulIcon.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import SwiftUI

struct TextWithColorfulIcon: View {
    let titleKey: LocalizedStringKey
    let systemName: String
    let foregroundColor: Color
    let backgroundColor: Color

    var body: some View {
        if #available(iOS 26.0, *) {
            HStack {
                Image(systemName: systemName)
                    .symbolRenderingMode(.hierarchical)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 18, height: 18)
                    .foregroundColor(foregroundColor)
                    .padding(6)
                    .background(backgroundColor.gradient)
                    .cornerRadius(7)
                    .overlay(
                        RoundedRectangle(cornerRadius: 7)
                            .strokeBorder(
                                LinearGradient(
                                    colors: [
                                        .white.opacity(0.8),
                                        .white.opacity(0.3),
                                        .clear,
                                        .clear
                                    ],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                ),
                                lineWidth: 0.5
                            )
                    )
                Text(titleKey)
            }
        } else {
            HStack {
                Image(systemName: systemName)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 18, height: 18)
                    .foregroundColor(foregroundColor)
                    .padding(6)
                    .background(backgroundColor.gradient)
                    .cornerRadius(7)
                Text(titleKey)
            }
        }
    }
}
