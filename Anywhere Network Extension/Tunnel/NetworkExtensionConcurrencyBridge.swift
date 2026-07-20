//
//  NetworkExtensionConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import NetworkExtension

extension NETunnelProviderSession: @unchecked @retroactive Sendable { }
extension NEPacketTunnelProvider: @unchecked @retroactive Sendable { }
extension NEPacketTunnelFlow: @unchecked @retroactive Sendable { }
