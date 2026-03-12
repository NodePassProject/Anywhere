//
//  DynamicSheet.swift
//  Anywhere
//
//  Created by Argsment Limited on 2/16/26.
//

import SwiftUI

struct DynamicSheet<Content: View>: View {
    var animation: Animation
    @ViewBuilder var content: Content
    @State private var sheetHeight: CGFloat = 320
    var body: some View {
        ZStack {
            content
                /// As this will fix the size of the view in the vertical direction!
                .fixedSize(horizontal: false, vertical: true)
                .onGeometryChange(for: CGSize.self) {
                    $0.size
                } action: { newValue in
                    withAnimation(animation) {
                        sheetHeight = min(newValue.height, windowSize.height - 110)
                    }
                }
        }
        .modifier(SheetHeightModifier(height: sheetHeight))
    }
    
    /// You can use property to limit the max height, but I'm using the window size height to do so!
    var windowSize: CGSize {
        if let size = (UIApplication.shared.connectedScenes.first as? UIWindowScene)?.screen.bounds.size {
            return size
        }
        
        return .zero
    }
}

fileprivate struct SheetHeightModifier: ViewModifier, Animatable {
    var height: CGFloat
    var animatableData: CGFloat {
        get { height }
        set { height = newValue }
    }
    func body(content: Content) -> some View {
        content
            .presentationDetents(height == .zero ? [.medium] : [.height(height)])
    }
}
