//
//  ConfigurationProvider.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

/// Protocol for loading VPN configurations
protocol ConfigurationProviding {
    func loadConfigurations() -> [VLESSConfiguration]
}
