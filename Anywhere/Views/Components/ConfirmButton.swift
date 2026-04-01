//
//  ConfirmButton.swift
//  MongoPie
//
//  Created by Argsment Limited on 3/31/26.
//

import SwiftUI

struct ConfirmButton: View {
    let titleKey: LocalizedStringKey
    let action: () -> Void
    
    init(_ titleKey: LocalizedStringKey, action: @escaping () -> Void) {
        self.titleKey = titleKey
        self.action = action
    }
    
    var body: some View {
        if #available(iOS 26.0, *) {
            Button(titleKey, systemImage: "checkmark", role: .confirm, action: action)
        }
        else {
            Button(titleKey, action: action)
        }
    }
}
