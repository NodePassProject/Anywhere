//
//  AWCore.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

final class AWCore {
    static let suiteName = "group.com.argsment.Anywhere"
    static let userDefaults = UserDefaults(suiteName: suiteName)!

    /// Moves a JSON file from the old documents directory to the App Group container if needed.
    static func migrateToAppGroup(fileName: String) {
        let fm = FileManager.default
        let oldURL = fm.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent(fileName)
        guard let container = fm.containerURL(forSecurityApplicationGroupIdentifier: suiteName) else { return }
        let newURL = container.appendingPathComponent(fileName)
        guard fm.fileExists(atPath: oldURL.path), !fm.fileExists(atPath: newURL.path) else { return }
        do {
            try fm.moveItem(at: oldURL, to: newURL)
        } catch {
            print("Failed to migrate \(fileName): \(error)")
        }
    }
}
