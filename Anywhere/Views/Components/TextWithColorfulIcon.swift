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
    
    init(title: String.LocalizationValue, comment: StaticString? = nil, systemName: String, foregroundStyle: F, backgroundStyle: B) {
        self.title = title
        self.comment = comment
        self.systemName = systemName
        self.foregroundStyle = foregroundStyle
        self.backgroundStyle = backgroundStyle
    }

    var body: some View {
        HStack {
            Image(systemName: systemName)
                .resizable()
                .scaledToFit()
                .frame(width: 18, height: 18)
                .foregroundStyle(foregroundStyle)
                .padding(5)
                .background(backgroundStyle)
                .clipShape(.rect(cornerRadius: 8))
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
    
    init(title: String.LocalizationValue, comment: StaticString? = nil, imageName: String, foregroundStyle: F, backgroundStyle: B) {
        self.title = title
        self.comment = comment
        self.imageName = imageName
        self.foregroundStyle = foregroundStyle
        self.backgroundStyle = backgroundStyle
    }

    var body: some View {
        HStack {
            Image(imageName)
                .interpolation(.high)
                .renderingMode(.template)
                .resizable()
                .scaledToFit()
                .frame(width: 18, height: 18)
                .foregroundStyle(foregroundStyle)
                .padding(5)
                .background(backgroundStyle)
                .clipShape(.rect(cornerRadius: 8))
            Text(String(localized: title, comment: comment))
        }
    }
}
