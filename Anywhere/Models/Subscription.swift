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

    init(id: UUID = UUID(), name: String, url: String, lastUpdate: Date? = nil, upload: Int64? = nil, download: Int64? = nil, total: Int64? = nil, expire: Date? = nil) {
        self.id = id
        self.name = name
        self.url = url
        self.lastUpdate = lastUpdate
        self.upload = upload
        self.download = download
        self.total = total
        self.expire = expire
    }
}
