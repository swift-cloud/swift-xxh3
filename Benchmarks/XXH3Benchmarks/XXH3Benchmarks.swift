import Benchmark
import XXH3

let benchmarks: @Sendable () -> Void = {
    // Test strings of various sizes
    let shortString = "Hello"
    let mediumString = "Hello, World! This is a medium length string for testing."
    let longString = String(repeating: "abcdefghij", count: 100)  // 1000 chars
    let veryLongString = String(repeating: "abcdefghij", count: 1000)  // 10000 chars

    // Pre-generate byte arrays for byte-based benchmarks
    let shortBytes = Array(shortString.utf8)
    let mediumBytes = Array(mediumString.utf8)
    let longBytes = Array(longString.utf8)
    let veryLongBytes = Array(veryLongString.utf8)

    // MARK: - XXH3 String Hashing Benchmarks

    Benchmark("XXH3 String (5 bytes)") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(XXH3.hash(shortString))
        }
    }

    Benchmark("XXH3 String (58 bytes)") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(XXH3.hash(mediumString))
        }
    }

    Benchmark("XXH3 String (1000 bytes)") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(XXH3.hash(longString))
        }
    }

    Benchmark("XXH3 String (10000 bytes)") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(XXH3.hash(veryLongString))
        }
    }

    // MARK: - Swift Hasher String Benchmarks

    Benchmark("Swift Hasher String (5 bytes)") { benchmark in
        for _ in benchmark.scaledIterations {
            var hasher = Hasher()
            hasher.combine(shortString)
            blackHole(hasher.finalize())
        }
    }

    Benchmark("Swift Hasher String (58 bytes)") { benchmark in
        for _ in benchmark.scaledIterations {
            var hasher = Hasher()
            hasher.combine(mediumString)
            blackHole(hasher.finalize())
        }
    }

    Benchmark("Swift Hasher String (1000 bytes)") { benchmark in
        for _ in benchmark.scaledIterations {
            var hasher = Hasher()
            hasher.combine(longString)
            blackHole(hasher.finalize())
        }
    }

    Benchmark("Swift Hasher String (10000 bytes)") { benchmark in
        for _ in benchmark.scaledIterations {
            var hasher = Hasher()
            hasher.combine(veryLongString)
            blackHole(hasher.finalize())
        }
    }

    // MARK: - XXH3 Byte Array Benchmarks

    Benchmark("XXH3 Bytes (5 bytes)") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(XXH3.hash(shortBytes, count: shortBytes.count))
        }
    }

    Benchmark("XXH3 Bytes (58 bytes)") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(XXH3.hash(mediumBytes, count: mediumBytes.count))
        }
    }

    Benchmark("XXH3 Bytes (1000 bytes)") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(XXH3.hash(longBytes, count: longBytes.count))
        }
    }

    Benchmark("XXH3 Bytes (10000 bytes)") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(XXH3.hash(veryLongBytes, count: veryLongBytes.count))
        }
    }

    // MARK: - XXH3 Integer Hashing

    Benchmark("XXH3 Integer") { benchmark in
        for i in benchmark.scaledIterations {
            blackHole(XXH3.hash(i))
        }
    }

    Benchmark("Swift Hasher Integer") { benchmark in
        for i in benchmark.scaledIterations {
            var hasher = Hasher()
            hasher.combine(i)
            blackHole(hasher.finalize())
        }
    }

    // MARK: - Throughput Benchmarks (bytes per second)

    Benchmark(
        "XXH3 Throughput (1KB)",
        configuration: .init(
            metrics: [.throughput, .wallClock],
            scalingFactor: .kilo
        )
    ) { benchmark in
        let data = Array(repeating: UInt8(0xAB), count: 1024)
        for _ in benchmark.scaledIterations {
            blackHole(XXH3.hash(data, count: data.count))
        }
    }

    Benchmark(
        "XXH3 Throughput (1MB)",
        configuration: .init(
            metrics: [.throughput, .wallClock],
            scalingFactor: .mega
        )
    ) { benchmark in
        let data = Array(repeating: UInt8(0xAB), count: 1024 * 1024)
        for _ in benchmark.scaledIterations {
            blackHole(XXH3.hash(data, count: data.count))
        }
    }
}
