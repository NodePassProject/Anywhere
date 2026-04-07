//
//  AWCore.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

enum ProxyMode: String, CaseIterable {
    case rule
    case global
}

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
    
    static func getProxyMode() -> ProxyMode {
        if let rawValue = userDefaults.string(forKey: "proxyMode") {
            return ProxyMode(rawValue: rawValue) ?? .rule
        } else {
            return .rule
        }
    }
    
    static func setProxyMode(_ proxyMode: ProxyMode) {
        userDefaults.set(proxyMode.rawValue, forKey: "proxyMode")
    }
    
    // MARK: - Darwin Notification Names

    enum Notification {
        static let settingsChanged = "com.argsment.Anywhere.settingsChanged" as CFString
        static let routingChanged = "com.argsment.Anywhere.routingChanged" as CFString
    }

    private static var lastPostTimes = [CFNotificationName: CFAbsoluteTime]()
    private static var pendingWorkItems = [CFNotificationName: DispatchWorkItem]()
    private static let postLock = NSLock()
    private static let throttleInterval: CFAbsoluteTime = 1.0

    private static func postThrottled(_ name: CFNotificationName) {
        postLock.lock()
        let now = CFAbsoluteTimeGetCurrent()
        let lastTime = lastPostTimes[name] ?? 0
        let elapsed = now - lastTime

        pendingWorkItems[name]?.cancel()

        if elapsed >= throttleInterval {
            lastPostTimes[name] = now
            postLock.unlock()
            CFNotificationCenterPostNotification(
                CFNotificationCenterGetDarwinNotifyCenter(), name, nil, nil, true
            )
        } else {
            let delay = throttleInterval - elapsed
            let item = DispatchWorkItem {
                postLock.lock()
                lastPostTimes[name] = CFAbsoluteTimeGetCurrent()
                pendingWorkItems[name] = nil
                postLock.unlock()
                CFNotificationCenterPostNotification(
                    CFNotificationCenterGetDarwinNotifyCenter(), name, nil, nil, true
                )
            }
            pendingWorkItems[name] = item
            postLock.unlock()
            DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: item)
        }
    }

    static func notifySettingsChanged() {
        postThrottled(CFNotificationName(Notification.settingsChanged))
    }

    static func notifyRoutingChanged() {
        postThrottled(CFNotificationName(Notification.routingChanged))
    }
}
