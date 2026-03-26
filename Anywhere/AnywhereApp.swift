//
//  AnywhereApp.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/23/26.
//

import SwiftUI

@main
struct AnywhereApp: App {
    init() {
        if !AWCore.userDefaults.bool(forKey: "initialSetupDone") {
            AWCore.userDefaults.set(true, forKey: "initialSetupDone")
            let languageToCountry: [String: String] = [
                "ar": "SA", "fa": "IR", "my": "MM", "ru": "RU",
                "tk": "TM", "vi": "VN", "zh": "CN", "be": "BY",
            ]
            if let langCode = Locale.current.language.languageCode?.identifier,
               let country = languageToCountry[langCode] {
                AWCore.userDefaults.set(country, forKey: "bypassCountryCode")
            }
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
