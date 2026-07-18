//
//  FoundationConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation

extension CFString: @unchecked @retroactive Sendable { }
extension Regex: @unchecked @retroactive Sendable { }
extension UserDefaults: @unchecked @retroactive Sendable { }
