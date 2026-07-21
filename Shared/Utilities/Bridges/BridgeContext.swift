//
//  BridgeContext.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

nonisolated enum BridgeContext {
    static func passRetained<T: AnyObject>(_ object: T) -> UnsafeMutableRawPointer {
        Unmanaged.passRetained(object).toOpaque()
    }
    
    static func passUnretained<T: AnyObject>(_ object: T) -> UnsafeMutableRawPointer {
        Unmanaged.passUnretained(object).toOpaque()
    }
    
    static func unretained<T: AnyObject>(
        _ pointer: UnsafeMutableRawPointer,
        as _: T.Type = T.self
    ) -> T {
        Unmanaged<T>.fromOpaque(pointer).takeUnretainedValue()
    }
    
    static func consume<T: AnyObject>(
        _ pointer: UnsafeMutableRawPointer,
        as _: T.Type = T.self
    ) -> T {
        Unmanaged<T>.fromOpaque(pointer).takeRetainedValue()
    }
    
    static func release<T: AnyObject>(_ object: T) {
        Unmanaged.passUnretained(object).release()
    }
}
