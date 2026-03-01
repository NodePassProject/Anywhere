//
//  AppIconView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/2/26.
//

import SwiftUI

struct AppIconView: View {
    let name: String
    
    init(_ name: String) {
        self.name = name
    }
    
    var body: some View {
        if #available(iOS 26.0, *) {
            Image(name)
                .resizable()
                .scaledToFit()
                .frame(width: 32, height: 32)
                .cornerRadius(7)
                .overlay(
                    RoundedRectangle(cornerRadius: 7)
                        .strokeBorder(
                            LinearGradient(
                                colors: [
                                    .white.opacity(0.6),
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
                .overlay(
                    RoundedRectangle(cornerRadius: 7)
                        .strokeBorder(
                            LinearGradient(
                                colors: [
                                    .clear,
                                    .clear,
                                    .white.opacity(0.1),
                                    .white.opacity(0.3)
                                ],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            ),
                            lineWidth: 0.5
                        )
                )
        }
        else {
            Image(name)
                .resizable()
                .scaledToFit()
                .frame(width: 32, height: 32)
                .cornerRadius(7)
        }
    }
}
