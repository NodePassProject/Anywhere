//
//  FailableDecodable.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
//

import Foundation

nonisolated final class DecodeLossTally: @unchecked Sendable {
    static let key = CodingUserInfoKey(rawValue: "AnywhereDecodeLossTally")!
    var dropped = 0
}

nonisolated struct FailableDecodable<T: Decodable>: Decodable {
    let value: T?
    init(from decoder: Decoder) throws {
        value = try? T(from: decoder)
        if value == nil, let tally = decoder.userInfo[DecodeLossTally.key] as? DecodeLossTally {
            tally.dropped += 1
        }
    }
}

nonisolated extension JSONDecoder {
    func decodeSkippingInvalid<T: Decodable>(
        _ type: [T].Type,
        from data: Data
    ) -> [T]? {
        guard let wrapped = try? decode([FailableDecodable<T>].self, from: data) else {
            return nil
        }
        return wrapped.compactMap(\.value)
    }
}

nonisolated extension KeyedDecodingContainer {
    func decodeSkippingInvalid<T: Decodable>(
        _ type: [T].Type,
        forKey key: Key
    ) throws -> [T] {
        let wrapped = try decode([FailableDecodable<T>].self, forKey: key)
        return wrapped.compactMap(\.value)
    }
}
