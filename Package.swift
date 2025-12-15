// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "XXH3",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
    ],
    products: [
        .library(name: "XXH3", targets: ["XXH3"])
    ],
    targets: [
        .target(
            name: "XXH3"
        ),
        .testTarget(
            name: "XXH3Tests",
            dependencies: [
                "XXH3"
            ]
        ),
    ]
)
