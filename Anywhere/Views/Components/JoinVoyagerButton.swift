//
//  JoinVoyagerButton.swift
//  Anywhere
//
//  Created by NodePassProject on 6/20/26.
//

import SwiftUI

struct JoinVoyagerButton: View {
    let action: () -> Void
    
    init(action: @escaping () -> Void) {
        self.action = action
    }
    
    var body: some View {
        Button(action: action) {
            Text("Join")
                .textCase(.uppercase)
                .font(.system(size: 14).weight(.semibold))
                .foregroundStyle(.white)
                .padding(.vertical, 8)
                .padding(.horizontal, 20)
                .background(Color(hex: 0x5060F0).gradient, in: Capsule())
        }
        .buttonStyle(.plain)
    }
}
