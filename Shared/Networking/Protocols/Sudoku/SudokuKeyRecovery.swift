//
//  SudokuKeyRecovery.swift
//  Anywhere
//
//  Created by saba-futai on 10/18/26.
//

import Foundation

nonisolated private struct SudokuUInt128 {
    var hi: UInt64
    var lo: UInt64
    static let zero = SudokuUInt128(hi: 0, lo: 0)
    init(_ value: UInt64) { hi = 0; lo = value }
    init(hi: UInt64, lo: UInt64) { self.hi = hi; self.lo = lo }
    mutating func add(_ other: SudokuUInt128) { let (newLo, carry) = lo.addingReportingOverflow(other.lo); lo = newLo; hi = hi &+ other.hi &+ (carry ? 1 : 0) }
    mutating func addProduct(_ a: UInt64, _ b: UInt64, multiplier: UInt64 = 1) { var wide = a.multipliedFullWidth(by: b); if multiplier != 1 { let loWide = wide.low.multipliedFullWidth(by: multiplier); let hiLow = wide.high &* multiplier; wide = (high: loWide.high &+ hiLow, low: loWide.low) }; add(SudokuUInt128(hi: wide.high, lo: wide.low)) }
    func shiftedRight(_ bits: UInt64) -> UInt64 { bits == 0 ? lo : ((hi << (64 - bits)) | (lo >> bits)) }
}

nonisolated private struct SudokuFE25519 {
    static let mask: UInt64 = (1 << 51) - 1
    static let p: [UInt64] = [2251799813685229, 2251799813685247, 2251799813685247, 2251799813685247, 2251799813685247]
    static let d2 = SudokuFE25519([1859910466990425, 932731440258426, 1072319116312658, 1815898335770999, 633789495995903])
    static let baseX = SudokuFE25519([1738742601995546, 1146398526822698, 2070867633025821, 562264141797630, 587772402128613])
    static let baseY = SudokuFE25519([1801439850948184, 1351079888211148, 450359962737049, 900719925474099, 1801439850948198])
    var v: [UInt64]
    init(_ v: [UInt64] = [0, 0, 0, 0, 0]) { self.v = v }
    static var one: SudokuFE25519 { SudokuFE25519([1, 0, 0, 0, 0]) }
    mutating func carry() { var c = v[0] >> 51; v[0] &= Self.mask; v[1] += c; c = v[1] >> 51; v[1] &= Self.mask; v[2] += c; c = v[2] >> 51; v[2] &= Self.mask; v[3] += c; c = v[3] >> 51; v[3] &= Self.mask; v[4] += c; c = v[4] >> 51; v[4] &= Self.mask; v[0] += c * 19; c = v[0] >> 51; v[0] &= Self.mask; v[1] += c }
    mutating func normalize() { carry(); carry(); if gteP() { subP() } }
    func gteP() -> Bool { for i in stride(from: 4, through: 0, by: -1) { if v[i] > Self.p[i] { return true }; if v[i] < Self.p[i] { return false } }; return true }
    mutating func subP() { var borrow: UInt64 = 0; for i in 0..<5 { let sub = Self.p[i] + borrow; let next = v[i] < sub ? UInt64(1) : UInt64(0); v[i] = v[i] &- sub; borrow = next } }
    static func + (f: SudokuFE25519, g: SudokuFE25519) -> SudokuFE25519 { var h = SudokuFE25519(); for i in 0..<5 { h.v[i] = f.v[i] + g.v[i] }; h.carry(); return h }
    static func - (f: SudokuFE25519, g: SudokuFE25519) -> SudokuFE25519 { var h = SudokuFE25519(); for i in 0..<5 { h.v[i] = f.v[i] + 4 * Self.p[i] - g.v[i] }; h.carry(); return h }
    static func * (f: SudokuFE25519, g: SudokuFE25519) -> SudokuFE25519 {
        var t = Array(repeating: SudokuUInt128.zero, count: 5)
        t[0].addProduct(f.v[0], g.v[0]); t[0].addProduct(f.v[1], g.v[4], multiplier: 19); t[0].addProduct(f.v[2], g.v[3], multiplier: 19); t[0].addProduct(f.v[3], g.v[2], multiplier: 19); t[0].addProduct(f.v[4], g.v[1], multiplier: 19)
        t[1].addProduct(f.v[0], g.v[1]); t[1].addProduct(f.v[1], g.v[0]); t[1].addProduct(f.v[2], g.v[4], multiplier: 19); t[1].addProduct(f.v[3], g.v[3], multiplier: 19); t[1].addProduct(f.v[4], g.v[2], multiplier: 19)
        t[2].addProduct(f.v[0], g.v[2]); t[2].addProduct(f.v[1], g.v[1]); t[2].addProduct(f.v[2], g.v[0]); t[2].addProduct(f.v[3], g.v[4], multiplier: 19); t[2].addProduct(f.v[4], g.v[3], multiplier: 19)
        t[3].addProduct(f.v[0], g.v[3]); t[3].addProduct(f.v[1], g.v[2]); t[3].addProduct(f.v[2], g.v[1]); t[3].addProduct(f.v[3], g.v[0]); t[3].addProduct(f.v[4], g.v[4], multiplier: 19)
        t[4].addProduct(f.v[0], g.v[4]); t[4].addProduct(f.v[1], g.v[3]); t[4].addProduct(f.v[2], g.v[2]); t[4].addProduct(f.v[3], g.v[1]); t[4].addProduct(f.v[4], g.v[0])
        var h = SudokuFE25519(); var carry = t[0].shiftedRight(51); t[1].add(SudokuUInt128(carry)); h.v[0] = t[0].lo & mask; carry = t[1].shiftedRight(51); t[2].add(SudokuUInt128(carry)); h.v[1] = t[1].lo & mask; carry = t[2].shiftedRight(51); t[3].add(SudokuUInt128(carry)); h.v[2] = t[2].lo & mask; carry = t[3].shiftedRight(51); t[4].add(SudokuUInt128(carry)); h.v[3] = t[3].lo & mask; carry = t[4].shiftedRight(51); h.v[4] = t[4].lo & mask; h.v[0] += carry * 19; h.carry(); return h
    }
    func squared() -> SudokuFE25519 { self * self }
    func inverted() -> SudokuFE25519 { var r = SudokuFE25519.one; let exp = SudokuKeyRecovery.pMinus2; for bit in stride(from: 254, through: 0, by: -1) { r = r.squared(); if ((exp[bit >> 3] >> UInt8(bit & 7)) & 1) != 0 { r = r * self } }; return r }
    func toBytes() -> [UInt8] { var h = self; h.normalize(); var out = Array(repeating: UInt8(0), count: 32); for i in 0..<32 { let bit = i * 8; let limb = bit / 51; let shift = bit % 51; var value = h.v[limb] >> UInt64(shift); if limb + 1 < 5 && shift > 43 { value |= h.v[limb + 1] << UInt64(51 - shift) }; out[i] = UInt8(truncatingIfNeeded: value) }; return out }
    func isOdd() -> Bool { (toBytes()[0] & 1) != 0 }
}

nonisolated private struct SudokuEdPoint {
    var x: SudokuFE25519; var y: SudokuFE25519; var z: SudokuFE25519; var t: SudokuFE25519
    static var identity: SudokuEdPoint { SudokuEdPoint(x: SudokuFE25519(), y: .one, z: .one, t: SudokuFE25519()) }
    static var base: SudokuEdPoint { let x = SudokuFE25519.baseX; let y = SudokuFE25519.baseY; return SudokuEdPoint(x: x, y: y, z: .one, t: x * y) }
    func adding(_ q: SudokuEdPoint) -> SudokuEdPoint {
        let yMinusX = y - x
        let qYMinusX = q.y - q.x
        let a = yMinusX * qYMinusX

        let yPlusX = y + x
        let qYPlusX = q.y + q.x
        let b = yPlusX * qYPlusX

        let tt = t * q.t
        let c = tt * SudokuFE25519.d2
        let zz = z * q.z
        let d = zz + zz

        let e = b - a
        let f = d - c
        let g = d + c
        let h = b + a
        return SudokuEdPoint(x: e * f, y: g * h, z: f * g, t: e * h)
    }

    func doubled() -> SudokuEdPoint {
        let a = x.squared()
        let b = y.squared()
        let z2 = z.squared()
        let c = z2 + z2
        let d = SudokuFE25519() - a
        let xy = x + y
        let e = (xy.squared() - a) - b
        let g = d + b
        let f = g - c
        let h = d - b
        return SudokuEdPoint(x: e * f, y: g * h, z: f * g, t: e * h)
    }
}

nonisolated enum SudokuKeyRecovery {
    fileprivate static let l: [UInt8] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]
    fileprivate static let pMinus2: [UInt8] = [0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]
    static func recoverPublicKeyHex(_ keyHex: String) -> String? { guard let raw = Data(hexString: keyHex), raw.count == 32 || raw.count == 64 else { return nil }; if raw.count == 32 { return raw.hexEncodedString() }; let scalar = scalarAdd(Array(raw.prefix(32)), Array(raw.suffix(32))); return Data(scalarBasePublic(scalar)).hexEncodedString() }
    private static func scalarAdd(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] { var out = Array(repeating: UInt8(0), count: 32); var carry = 0; for i in 0..<32 { let sum = Int(a[i]) + Int(b[i]) + carry; out[i] = UInt8(truncatingIfNeeded: sum); carry = sum >> 8 }; if carry != 0 || scalarGteL(out) { scalarSubL(&out) }; return out }
    private static func scalarGteL(_ s: [UInt8]) -> Bool { for i in stride(from: 31, through: 0, by: -1) { if s[i] > l[i] { return true }; if s[i] < l[i] { return false } }; return true }
    private static func scalarSubL(_ s: inout [UInt8]) { var borrow = 0; for i in 0..<32 { let sub = Int(l[i]) + borrow; let current = Int(s[i]); s[i] = UInt8(truncatingIfNeeded: current - sub); borrow = current < sub ? 1 : 0 } }
    private static func scalarBasePublic(_ scalar: [UInt8]) -> [UInt8] { var result = SudokuEdPoint.identity; let base = SudokuEdPoint.base; for bit in stride(from: 255, through: 0, by: -1) { result = result.doubled(); if ((scalar[bit >> 3] >> UInt8(bit & 7)) & 1) != 0 { result = result.adding(base) } }; let zInv = result.z.inverted(); let x = result.x * zInv; let y = result.y * zInv; var out = y.toBytes(); if x.isOdd() { out[31] |= 0x80 } else { out[31] &= 0x7f }; return out }
}
