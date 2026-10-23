//
//  FixedWidthInteger+Rotation.swift
//  BLAKE
//
//  Created by NodePassProject on 10/23/26.
//

extension FixedWidthInteger where Self: UnsignedInteger {
    @inline(__always)
    func rotatedRight(by count: Int) -> Self {
        (self &>> count) | (self &<< (Self.bitWidth &- count))
    }
}
