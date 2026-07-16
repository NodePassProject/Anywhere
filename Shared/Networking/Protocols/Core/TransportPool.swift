//
//  TransportPool.swift
//  Anywhere
//
//  Created by NodePassProject on 7/13/26.
//

nonisolated protocol TransportPool: AnyObject {
    func reclaim()
}
