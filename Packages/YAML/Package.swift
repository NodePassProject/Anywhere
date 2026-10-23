// swift-tools-version: 6.4

import PackageDescription

let package = Package(
    name: "YAML",
    platforms: [
        .iOS(.v18),
        .macOS(.v15),
        .tvOS(.v18),
        .watchOS(.v11),
    ],
    products: [
        .library(
            name: "YAML",
            targets: ["YAML"]
        ),
    ],
    targets: [
        .target(
            name: "YAML"
        ),
    ]
)
