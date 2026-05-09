//
//  FailableDecodable.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/9/26.
//

import Foundation

/// Wraps a `Decodable` so a single element's failure doesn't fail the
/// whole array. Used by every persistent store's `load()` so a corrupt
/// or schema-changed entry preserves the rest of the user's data
/// instead of wiping it.
struct FailableDecodable<T: Decodable>: Decodable {
    let value: T?
    init(from decoder: Decoder) throws {
        value = try? T(from: decoder)
    }
}

extension JSONDecoder {
    /// Decodes `[T]` from `data`, silently dropping any element that
    /// fails to decode. Returns nil only when the surrounding JSON
    /// isn't an array of objects at all.
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
    /// Decodes `[T]` for ``key``, silently dropping elements that fail
    /// to decode. Throws only when the key is missing or its value
    /// isn't an array.
    func decodeSkippingInvalid<T: Decodable>(
        _ type: [T].Type,
        forKey key: Key
    ) throws -> [T] {
        let wrapped = try decode([FailableDecodable<T>].self, forKey: key)
        return wrapped.compactMap(\.value)
    }
}
