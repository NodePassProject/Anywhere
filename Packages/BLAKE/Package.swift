// swift-tools-version: 6.4

import PackageDescription

let package = Package(
    name: "BLAKE",
    platforms: [
        .iOS(.v18),
        .macOS(.v15),
        .tvOS(.v18),
        .watchOS(.v11),
    ],
    products: [
        .library(
            name: "BLAKE",
            targets: ["BLAKE"]
        ),
    ],
    targets: [
        .target(
            name: "BLAKE"
        ),
    ]
)
