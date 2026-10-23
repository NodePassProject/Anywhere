//
//  Node+Parsing.swift
//  YAML
//
//  Created by NodePassProject on 10/23/26.
//

extension Node {
    public init(yaml: String) throws(YAMLError) {
        var composer = try Composer(yaml)
        self = try composer.composeDocument() ?? .null
    }
}
