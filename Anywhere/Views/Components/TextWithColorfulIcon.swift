//
//  TextWithColorfulIcon.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import SwiftUI

struct TextWithColorfulIcon: View {
    let title: String.LocalizationValue
    let comment: StaticString?
    let systemName: String
    let foregroundColor: Color
    let backgroundColor: Color

    var body: some View {
        HStack {
            Image(systemName: systemName)
                .resizable()
                .scaledToFit()
                .frame(width: 19, height: 19)
                .foregroundStyle(foregroundColor)
                .padding(5)
                .background(backgroundColor)
                .clipShape(.rect(cornerRadius: 7))
            Text(String(localized: title, comment: comment))
        }
    }
}

struct TextWithColorfulIconAndCustomImage: View {
    let title: String.LocalizationValue
    let comment: StaticString?
    let imageName: String
    let foregroundColor: Color
    let backgroundColor: Color

    var body: some View {
        HStack {
            Image(imageName)
                .interpolation(.high)
                .renderingMode(.template)
                .resizable()
                .scaledToFit()
                .frame(width: 19, height: 19)
                .foregroundStyle(foregroundColor)
                .padding(5)
                .background(backgroundColor)
                .clipShape(.rect(cornerRadius: 7))
            Text(String(localized: title, comment: comment))
        }
    }
}
