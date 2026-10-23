//
//  YAMLError.swift
//  YAML
//
//  Created by NodePassProject on 10/23/26.
//

public struct YAMLError: Error, Hashable, Sendable {
    public struct Location: Hashable, Sendable {
        public let line: Int
        public let column: Int

        public init(line: Int, column: Int) {
            self.line = line
            self.column = column
        }
    }

    public let problem: String
    public let location: Location
    public let context: String?
    public let contextLocation: Location?

    init(problem: String, mark: Mark, context: String? = nil, contextMark: Mark? = nil) {
        self.problem = problem
        self.location = Location(mark)
        self.context = context
        self.contextLocation = context == nil ? nil : contextMark.map(Location.init)
    }
}

extension YAMLError: CustomStringConvertible {
    public var description: String {
        var description = "\(problem) at \(location)"
        if let context, let contextLocation {
            description += ", \(context) at \(contextLocation)"
        }
        return description
    }
}

extension YAMLError.Location: CustomStringConvertible {
    public var description: String {
        "line \(line), column \(column)"
    }
}

extension YAMLError.Location {
    init(_ mark: Mark) {
        self.init(line: mark.line + 1, column: mark.column + 1)
    }
}
