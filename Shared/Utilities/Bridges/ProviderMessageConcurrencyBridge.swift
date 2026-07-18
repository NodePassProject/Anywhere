//
//  ProviderMessageConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import NetworkExtension

nonisolated enum ProviderMessageConcurrencyBridge {
    static func send(_ messageData: Data, over session: NETunnelProviderSession) async -> Data? {
        await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(messageData) { response in
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(returning: nil)
            }
        }
    }
}
