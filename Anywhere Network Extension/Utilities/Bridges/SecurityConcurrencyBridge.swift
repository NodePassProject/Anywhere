//
//  SecurityConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Security

extension SecCertificate: @unchecked @retroactive Sendable { }
extension SecKey: @unchecked @retroactive Sendable { }
