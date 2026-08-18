//
//  AppIconView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/2/26.
//

import SwiftUI

struct AppIconView: View {
    let name: String
    
    init(_ name: String) {
        self.name = name
    }
    
    var body: some View {
        Image(name)
            .interpolation(.high)
            .resizable()
            .scaledToFit()
            .frame(width: 32, height: 32)
            .clipShape(.rect(cornerRadius: 7))
            .overlay(
                RoundedRectangle(cornerRadius: 7)
                    .strokeBorder(.gray.opacity(0.2), lineWidth: 1)
            )
    }
}
