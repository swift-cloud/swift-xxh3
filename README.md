# XXH3

A pure Swift implementation of the [XXH3](https://github.com/Cyan4973/xxHash) hash algorithm - an extremely fast, high-quality non-cryptographic hash function.

## Features

- Pure Swift implementation with no external dependencies
- Fully compatible with the official XXH3 reference implementation
- Optimized for performance with `@inlinable` annotations
- Supports all input sizes (0 bytes to arbitrary length)
- Optional seed parameter for hash variation
- Multiple convenient APIs for different input types
- Swift 6.2+ with strict concurrency support

## Installation

### Swift Package Manager

Add XXH3 to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/swift-cloud/swift-xxh3", from: "1.0.0")
]
```

Then add it to your target dependencies:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "XXH3", package: "swift-xxh3"),
    ]
)
```

## Usage

### Hashing Bytes

```swift
import XXH3

// Hash a byte array
let bytes: [UInt8] = [0x01, 0x02, 0x03, 0x04]
let hash = XXH3.hash(bytes, count: bytes.count)

// Hash with a seed
let seededHash = XXH3.hash(bytes, count: bytes.count, seed: 42)

// Hash any Sequence of UInt8
let data: Data = ...
let dataHash = XXH3.hash(data)
```

### Hashing Strings

```swift
import XXH3

let hash = XXH3.hash("Hello, World!")

// With a seed
let seededHash = XXH3.hash("Hello, World!", seed: 12345)
```

### Hashing Integers

```swift
import XXH3

let hash = XXH3.hash(42)
let negativeHash = XXH3.hash(-1)
```

### Hashing Any Hashable Type

```swift
import XXH3

struct Point: Hashable {
    let x: Int
    let y: Int
}

let point = Point(x: 10, y: 20)
let hash = XXH3.hash(point)
```

### Raw Pointer API

For maximum performance when working with raw memory:

```swift
import XXH3

let buffer: UnsafePointer<UInt8> = ...
let hash = XXH3.hash(buffer, count: bufferLength, seed: 0)
```

## API Reference

### Core Methods

```swift
// Hash any sequence of bytes
static func hash(_ bytes: some Sequence<UInt8>, seed: UInt64 = 0) -> Int64

// Hash a byte array with explicit count
static func hash(_ bytes: [UInt8], count: Int, seed: UInt64 = 0) -> Int64

// Hash raw bytes via pointer
static func hash(_ bytes: UnsafePointer<UInt8>, count: Int, seed: UInt64 = 0) -> Int64

// Hash a string
static func hash(_ string: String, seed: UInt64 = 0) -> Int64

// Hash an integer
static func hash(_ value: Int, seed: UInt64 = 0) -> Int64

// Hash any Hashable value
static func hash<T: Hashable>(_ value: T, seed: UInt64 = 0) -> Int64
```

### Return Type

All hash methods return `Int64`. This is intentional to make the result directly usable for:
- Array indexing with modulo operations
- Hash table implementations
- Consistent cross-platform behavior

## Performance

XXH3 is designed for speed. The implementation uses:

- Different optimized paths based on input length:
  - 0-16 bytes: Specialized fast path
  - 17-128 bytes: Accumulator-based mixing
  - 129-240 bytes: Extended mixing with avalanche
  - 240+ bytes: Block-based processing with scrambling
- `@inlinable` and `@inline(__always)` for critical paths
- Efficient 128-bit multiplication with fold
- SIMD-friendly accumulator design

### Benchmarks

Benchmarks comparing XXH3 to Swift's built-in `Hasher` (using [package-benchmark](https://github.com/ordo-one/package-benchmark)):

#### String Hashing (wall clock time, p50)

| Input Size | XXH3 | Swift Hasher | Winner |
|------------|------|--------------|--------|
| 5 bytes | 417 ns | 500 ns | XXH3 ~1.2x faster |
| 58 bytes | 458 ns | 500 ns | XXH3 ~1.1x faster |
| 1000 bytes | 500 ns | 542 ns | XXH3 ~1.1x faster |
| 10000 bytes | 833 ns | 833 ns | Tie |

#### Integer Hashing (wall clock time, p50)

| Operation | XXH3 | Swift Hasher |
|-----------|------|--------------|
| Single Int | 417 ns | 500 ns |

#### Throughput

| Input Size | Throughput |
|------------|------------|
| 1 KB | ~27 GB/s |
| 1 MB | ~27 GB/s |

*Benchmarks run on Apple M4 Pro. Run `swift package benchmark` to reproduce.*

## Algorithm Details

This implementation follows the XXH3 specification:

- Uses the standard 192-byte default secret
- Implements all length-specific hash functions
- Supports seeded hashing for all input sizes
- Produces 64-bit hash values

### Length-Specific Processing

| Input Length | Method |
|--------------|--------|
| 0 bytes | Secret-based initialization |
| 1-3 bytes | Combined byte mixing |
| 4-8 bytes | RRMXMX avalanche |
| 9-16 bytes | 128-bit multiply-fold |
| 17-128 bytes | Iterative 16-byte mixing |
| 129-240 bytes | Extended mixing with rounds |
| 240+ bytes | Block accumulation with scrambling |

## Compatibility

This implementation produces output identical to the official [xxHash](https://github.com/Cyan4973/xxHash) reference implementation. The test suite includes reference test vectors from the official implementation to ensure compatibility.

## Requirements

- Swift 6.2+
- macOS, iOS, tvOS, watchOS, visionOS, or Linux

## License

MIT License

## Credits

- Original [xxHash](https://github.com/Cyan4973/xxHash) algorithm by Yann Collet
- Swift implementation by Andrew Barba

## See Also

- [xxHash Official Repository](https://github.com/Cyan4973/xxHash)
- [XXH3 Specification](https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md)
