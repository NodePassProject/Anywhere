//
//  CancelButton.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/31/26.
//

import SwiftUI

struct CancelButton: View {
    let titleKey: LocalizedStringKey
    let action: () -> Void
    
    init(_ titleKey: LocalizedStringKey, action: @escaping () -> Void) {
        self.titleKey = titleKey
        self.action = action
    }
    
    var body: some View {
        if #available(iOS 26.0, *) {
            Button(titleKey, systemImage: "xmark", role: .cancel, action: action)
        }
        else {
            Button(titleKey, action: action)
        }
    }
}
