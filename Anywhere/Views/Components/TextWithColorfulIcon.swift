//
//  TextWithColorfulIcon.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import SwiftUI

struct TextWithColorfulIcon<F, B>: View where F : ShapeStyle, B : ShapeStyle {
    let title: String.LocalizationValue
    let comment: StaticString?
    let systemName: String
    let foregroundStyle: F
    let backgroundStyle: B

    var body: some View {
        HStack {
            Image(systemName: systemName)
                .resizable()
                .scaledToFit()
                .frame(width: 19, height: 19)
                .foregroundStyle(foregroundStyle)
                .padding(5)
                .background(backgroundStyle)
                .clipShape(.rect(cornerRadius: 7))
            Text(String(localized: title, comment: comment))
        }
    }
}

struct TextWithColorfulIconAndCustomImage<F, B>: View where F : ShapeStyle, B : ShapeStyle {
    let title: String.LocalizationValue
    let comment: StaticString?
    let imageName: String
    let foregroundStyle: F
    let backgroundStyle: B

    var body: some View {
        HStack {
            Image(imageName)
                .interpolation(.high)
                .renderingMode(.template)
                .resizable()
                .scaledToFit()
                .frame(width: 19, height: 19)
                .foregroundStyle(foregroundStyle)
                .padding(5)
                .background(backgroundStyle)
                .clipShape(.rect(cornerRadius: 7))
            Text(String(localized: title, comment: comment))
        }
    }
}
