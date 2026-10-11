// swift-tools-version: 6.4

import PackageDescription

let package = Package(
    name: "AnywhereQUIC",
    platforms: [
        .iOS(.v18),
        .macOS(.v15),
        .tvOS(.v18),
        .watchOS(.v11),
    ],
    products: [
        .library(
            name: "AnywhereQUIC",
            targets: ["AnywhereQUIC"]
        )
    ],
    targets: [
        .target(
            name: "AnywhereQUIC"
        ),
    ]
)
