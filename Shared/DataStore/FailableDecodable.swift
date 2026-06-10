//
//  FailableDecodable.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
//

import Foundation

/// Wraps a `Decodable` so a single corrupt element doesn't fail the whole
/// array and wipe the rest of the user's data.
struct FailableDecodable<T: Decodable>: Decodable {
    let value: T?
    init(from decoder: Decoder) throws {
        value = try? T(from: decoder)
    }
}

extension JSONDecoder {
    /// Decodes `[T]`, dropping elements that fail; nil only when the JSON isn't an array at all.
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

extension KeyedDecodingContainer {
    /// Decodes `[T]` for `key`, dropping elements that fail; throws only when the key is missing or not an array.
    func decodeSkippingInvalid<T: Decodable>(
        _ type: [T].Type,
        forKey key: Key
    ) throws -> [T] {
        let wrapped = try decode([FailableDecodable<T>].self, forKey: key)
        return wrapped.compactMap(\.value)
    }
}
