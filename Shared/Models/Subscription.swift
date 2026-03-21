//
//  Subscription.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

struct Subscription: Identifiable, Codable {
    let id: UUID
    var name: String
    var url: String
    var lastUpdate: Date?
    var upload: Int64?
    var download: Int64?
    var total: Int64?
    var expire: Date?
    var collapsed: Bool
    var isNameCustomized: Bool

    init(id: UUID = UUID(), name: String, url: String, lastUpdate: Date? = nil, upload: Int64? = nil, download: Int64? = nil, total: Int64? = nil, expire: Date? = nil, collapsed: Bool = false, isNameCustomized: Bool = false) {
        self.id = id
        self.name = name
        self.url = url
        self.lastUpdate = lastUpdate
        self.upload = upload
        self.download = download
        self.total = total
        self.expire = expire
        self.collapsed = collapsed
        self.isNameCustomized = isNameCustomized
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        url = try container.decode(String.self, forKey: .url)
        lastUpdate = try container.decodeIfPresent(Date.self, forKey: .lastUpdate)
        upload = try container.decodeIfPresent(Int64.self, forKey: .upload)
        download = try container.decodeIfPresent(Int64.self, forKey: .download)
        total = try container.decodeIfPresent(Int64.self, forKey: .total)
        expire = try container.decodeIfPresent(Date.self, forKey: .expire)
        collapsed = (try? container.decode(Bool.self, forKey: .collapsed)) ?? false
        isNameCustomized = (try? container.decode(Bool.self, forKey: .isNameCustomized)) ?? false
    }
}
