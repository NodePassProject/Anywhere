//
//  WatchConnectivityConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation

nonisolated enum WatchConnectivityConcurrencyBridge {
    struct ReplyHandler: @unchecked Sendable {
        private let handler: ([String: Any]) -> Void

        init(_ handler: @escaping ([String: Any]) -> Void) {
            self.handler = handler
        }

        func callAsFunction(_ reply: [String: Any]) {
            handler(reply)
        }
    }
}
