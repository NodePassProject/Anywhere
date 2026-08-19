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
            .frame(width: 30, height: 30)
            .clipShape(.rect(cornerRadius: 8))
    }
}
