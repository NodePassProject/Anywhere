//
//  TransportPool.swift
//  Anywhere
//
//  Created by NodePassProject on 7/13/26.
//

protocol TransportPool: AnyObject {
    func reclaim()
}
