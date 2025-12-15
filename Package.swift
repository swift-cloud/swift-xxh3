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
    dependencies: [
        .package(url: "https://github.com/ordo-one/package-benchmark", from: "1.0.0")
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
        .executableTarget(
            name: "XXH3Benchmarks",
            dependencies: [
                "XXH3",
                .product(name: "Benchmark", package: "package-benchmark"),
            ],
            path: "Benchmarks/XXH3Benchmarks",
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark")
            ]
        ),
    ]
)
