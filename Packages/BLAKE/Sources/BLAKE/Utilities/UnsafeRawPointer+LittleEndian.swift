//
//  UnsafeRawPointer+LittleEndian.swift
//  BLAKE
//
//  Created by NodePassProject on 10/23/26.
//

extension UnsafeRawPointer {
    @inline(__always)
    func loadLittleEndian<T: FixedWidthInteger>(fromByteOffset offset: Int, as type: T.Type) -> T {
        T(littleEndian: loadUnaligned(fromByteOffset: offset, as: T.self))
    }
}

extension UnsafeMutableRawPointer {
    @inline(__always)
    func storeLittleEndian<T: FixedWidthInteger>(_ value: T, toByteOffset offset: Int) {
        storeBytes(of: value.littleEndian, toByteOffset: offset, as: T.self)
    }
}
