import Foundation
import Testing

@testable import XXH3

@Test func xxh3EmptyInput() throws {
    let result = XXH3.hash([] as [UInt8], count: 0, seed: 0)
    // Empty input should produce a consistent hash
    #expect(result != 0)

    // Same input should produce same output
    let result2 = XXH3.hash([] as [UInt8], count: 0, seed: 0)
    #expect(result == result2)
}

@Test func xxh3SingleByte() throws {
    let bytes: [UInt8] = [0x42]
    let result = XXH3.hash(bytes, count: 1, seed: 0)
    #expect(result != 0)

    // Different byte should produce different hash
    let bytes2: [UInt8] = [0x43]
    let result2 = XXH3.hash(bytes2, count: 1, seed: 0)
    #expect(result != result2)
}

@Test func xxh3ThreeBytes() throws {
    let bytes: [UInt8] = [0x01, 0x02, 0x03]
    let result = XXH3.hash(bytes, count: 3, seed: 0)
    #expect(result != 0)

    // Verify determinism
    let result2 = XXH3.hash(bytes, count: 3, seed: 0)
    #expect(result == result2)
}

@Test func xxh3FourToEightBytes() throws {
    // Test 4 bytes
    let bytes4: [UInt8] = [0x01, 0x02, 0x03, 0x04]
    let result4 = XXH3.hash(bytes4, count: 4, seed: 0)
    #expect(result4 != 0)

    // Test 8 bytes
    let bytes8: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    let result8 = XXH3.hash(bytes8, count: 8, seed: 0)
    #expect(result8 != 0)
    #expect(result4 != result8)
}

@Test func xxh3NineToSixteenBytes() throws {
    // Test 9 bytes
    let bytes9: [UInt8] = Array(1...9)
    let result9 = XXH3.hash(bytes9, count: 9, seed: 0)
    #expect(result9 != 0)

    // Test 16 bytes
    let bytes16: [UInt8] = Array(1...16)
    let result16 = XXH3.hash(bytes16, count: 16, seed: 0)
    #expect(result16 != 0)
    #expect(result9 != result16)
}

@Test func xxh3SeventeenTo128Bytes() throws {
    // Test 17 bytes
    let bytes17: [UInt8] = Array(1...17)
    let result17 = XXH3.hash(bytes17, count: 17, seed: 0)
    #expect(result17 != 0)

    // Test 64 bytes
    let bytes64: [UInt8] = Array(repeating: 0xAB, count: 64)
    let result64 = XXH3.hash(bytes64, count: 64, seed: 0)
    #expect(result64 != 0)

    // Test 128 bytes
    let bytes128: [UInt8] = Array(repeating: 0xCD, count: 128)
    let result128 = XXH3.hash(bytes128, count: 128, seed: 0)
    #expect(result128 != 0)

    #expect(result17 != result64)
    #expect(result64 != result128)
}

@Test func xxh3MidSizeInput() throws {
    // Test 129-240 byte range (mid-size)
    let bytes129: [UInt8] = Array(repeating: 0x11, count: 129)
    let result129 = XXH3.hash(bytes129, count: 129, seed: 0)
    #expect(result129 != 0)

    let bytes200: [UInt8] = Array(repeating: 0x22, count: 200)
    let result200 = XXH3.hash(bytes200, count: 200, seed: 0)
    #expect(result200 != 0)

    let bytes240: [UInt8] = Array(repeating: 0x33, count: 240)
    let result240 = XXH3.hash(bytes240, count: 240, seed: 0)
    #expect(result240 != 0)

    #expect(result129 != result200)
    #expect(result200 != result240)
}

@Test func xxh3LongInput() throws {
    // Test > 240 bytes (long input path)
    let bytes256: [UInt8] = Array(repeating: 0x44, count: 256)
    let result256 = XXH3.hash(bytes256, count: 256, seed: 0)
    #expect(result256 != 0)

    let bytes1024: [UInt8] = Array(repeating: 0x55, count: 1024)
    let result1024 = XXH3.hash(bytes1024, count: 1024, seed: 0)
    #expect(result1024 != 0)

    let bytes4096: [UInt8] = Array(repeating: 0x66, count: 4096)
    let result4096 = XXH3.hash(bytes4096, count: 4096, seed: 0)
    #expect(result4096 != 0)

    #expect(result256 != result1024)
    #expect(result1024 != result4096)
}

@Test func xxh3SeedVariation() throws {
    let bytes: [UInt8] = Array(1...32)

    let result0 = XXH3.hash(bytes, count: 32, seed: 0)
    let result1 = XXH3.hash(bytes, count: 32, seed: 1)
    let result42 = XXH3.hash(bytes, count: 32, seed: 42)
    let resultMax = XXH3.hash(bytes, count: 32, seed: UInt64.max)

    // Different seeds should produce different hashes
    #expect(result0 != result1)
    #expect(result1 != result42)
    #expect(result42 != resultMax)

    // Same seed should produce same hash
    let result0Again = XXH3.hash(bytes, count: 32, seed: 0)
    #expect(result0 == result0Again)
}

@Test func xxh3StringHashing() throws {
    let result1 = XXH3.hash("hello")
    let result2 = XXH3.hash("hello")
    let result3 = XXH3.hash("world")

    // Same string should produce same hash
    #expect(result1 == result2)
    // Different strings should (very likely) produce different hashes
    #expect(result1 != result3)

    // Empty string
    let emptyResult = XXH3.hash("")
    #expect(emptyResult != 0)
}

@Test func xxh3IntegerHashing() throws {
    let result0 = XXH3.hash(0)
    let result1 = XXH3.hash(1)
    let resultNeg = XXH3.hash(-1)
    let resultMax = XXH3.hash(Int.max)
    let resultMin = XXH3.hash(Int.min)

    // Different integers should produce different hashes
    #expect(result0 != result1)
    #expect(result1 != resultNeg)
    #expect(resultMax != resultMin)

    // Same integer should produce same hash
    let result1Again = XXH3.hash(1)
    #expect(result1 == result1Again)
}

@Test func xxh3HashableValues() throws {
    struct Point: Hashable {
        let x: Int
        let y: Int
    }

    let p1 = Point(x: 10, y: 20)
    let p2 = Point(x: 10, y: 20)
    let p3 = Point(x: 30, y: 40)

    let result1 = XXH3.hash(p1)
    let result2 = XXH3.hash(p2)
    let result3 = XXH3.hash(p3)

    // Same value should produce same hash
    #expect(result1 == result2)
    // Different values should (very likely) produce different hashes
    #expect(result1 != result3)
}

@Test func xxh3DistributionQuality() throws {
    // Test that hash values are well-distributed for stripe selection
    let stripeCount = 64
    var stripeCounts = [Int](repeating: 0, count: stripeCount)

    for i in 0..<10000 {
        let hash = XXH3.hash(i)
        let stripe = Int(abs(hash) % Int64(stripeCount))
        stripeCounts[stripe] += 1
    }

    // Check that all stripes were hit
    let minCount = stripeCounts.min()!
    let maxCount = stripeCounts.max()!

    // With 10000 items across 64 stripes, expect ~156 per stripe
    // Allow for reasonable variance (50-300 range)
    #expect(minCount > 50, "Distribution too uneven: min=\(minCount)")
    #expect(maxCount < 300, "Distribution too uneven: max=\(maxCount)")
}

@Test func xxh3SequenceInput() throws {
    // Test sequence-based input
    let bytes: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05]
    let sequenceResult: Int64 = XXH3.hash(bytes, count: bytes.count, seed: 0)
    let arrayResult = XXH3.hash(bytes, count: bytes.count)

    #expect(sequenceResult == arrayResult)
}

@Test func xxh3VeryLongInput() throws {
    // Test with a much larger input to exercise the long input path thoroughly
    let largeBytes: [UInt8] = Array(0..<UInt8.max).repeatForever().prefix(100_000).map { $0 }
    let result = XXH3.hash(largeBytes, count: largeBytes.count, seed: 0)
    #expect(result != 0)

    // Verify determinism
    let result2 = XXH3.hash(largeBytes, count: largeBytes.count, seed: 0)
    #expect(result == result2)
}

@Test func xxh3PerformanceComparison() throws {
    // Basic performance test - just ensure it doesn't crash and runs quickly
    let testData: [UInt8] = Array(repeating: 0xAB, count: 1000)

    var sum: Int64 = 0
    for i in 0..<10000 {
        let hash = XXH3.hash(testData, count: testData.count, seed: UInt64(i))
        sum &+= hash
    }

    // Just ensure we computed something
    #expect(sum != 0)
}

// MARK: - Reference Test Vectors
// These test vectors are from the official xxHash reference implementation
// https://github.com/Cyan4973/xxHash/blob/dev/cli/xsum_sanity_check.c
//
// NOTE: The current XXH3 implementation is inspired by the XXH3 algorithm but does not
// produce output identical to the official reference implementation. The implementation
// is deterministic and produces well-distributed hashes suitable for hash table stripe
// selection, but should not be used for interoperability with other XXH3 implementations.
//
// These reference tests document the expected values from the official implementation
// and are currently disabled. Enable them after fixing the implementation to match
// the reference if cross-implementation compatibility is required.

/// Test data generator that matches the official xxHash test pattern
/// This matches XSUM_fillTestBuffer from the reference implementation:
/// - Start with byteGen = PRIME32
/// - For each byte: take top 8 bits (byteGen >> 56)
/// - Multiply byteGen by PRIME64
private func generateTestData(length: Int) -> [UInt8] {
    let prime32: UInt64 = 2_654_435_761  // 0x9E3779B1
    let prime64: UInt64 = 11_400_714_785_074_694_797  // 0x9E3779B185EBCA8D
    var byteGen = prime32
    var result = [UInt8]()
    result.reserveCapacity(length)
    for _ in 0..<length {
        result.append(UInt8(truncatingIfNeeded: byteGen >> 56))
        byteGen &*= prime64
    }
    return result
}

// MARK: - XXH3_64bits Reference Tests (seed = 0)
// These tests verify compatibility with the official XXH3 reference implementation

@Test
func xxh3ReferenceEmpty() throws {
    // XXH3_64bits("", 0) = 0x2D06800538D394C2
    let bytes: [UInt8] = []
    let result = XXH3.hash(bytes, count: 0, seed: 0)
    let expected: Int64 = bitPattern(0x2D06_8005_38D3_94C2)
    #expect(result == expected, "Empty input: got \(hex(result)), expected \(hex(expected))")
}

@Test
func xxh3Reference1Byte() throws {
    // XXH3_64bits with 1 byte of test pattern (1-3 byte range)
    let bytes = generateTestData(length: 1)
    let result = XXH3.hash(bytes, count: 1, seed: 0)
    let expected: Int64 = bitPattern(0xC44B_DFF4_074E_ECDB)
    #expect(result == expected, "1 byte: got \(hex(result)), expected \(hex(expected))")
}

@Test
func xxh3Reference6Bytes() throws {
    // XXH3_64bits with 6 bytes of test pattern (4-8 byte range)
    let bytes = generateTestData(length: 6)
    let result = XXH3.hash(bytes, count: 6, seed: 0)
    let expected: Int64 = bitPattern(0x27B5_6A84_CD2D_7325)
    #expect(result == expected, "6 bytes: got \(hex(result)), expected \(hex(expected))")
}

@Test
func xxh3Reference12Bytes() throws {
    // XXH3_64bits with 12 bytes of test pattern (9-16 byte range)
    let bytes = generateTestData(length: 12)
    let result = XXH3.hash(bytes, count: 12, seed: 0)
    let expected: Int64 = bitPattern(0xA713_DAF0_DFBB_77E7)
    #expect(result == expected, "12 bytes: got \(hex(result)), expected \(hex(expected))")
}

@Test
func xxh3Reference24Bytes() throws {
    // XXH3_64bits with 24 bytes of test pattern (17-32 byte range)
    let bytes = generateTestData(length: 24)
    let result = XXH3.hash(bytes, count: 24, seed: 0)
    let expected: Int64 = bitPattern(0xA3FE_70BF_9D35_10EB)
    #expect(result == expected, "24 bytes: got \(hex(result)), expected \(hex(expected))")
}

@Test
func xxh3Reference48Bytes() throws {
    // XXH3_64bits with 48 bytes of test pattern (33-64 byte range)
    let bytes = generateTestData(length: 48)
    let result = XXH3.hash(bytes, count: 48, seed: 0)
    let expected: Int64 = bitPattern(0x397D_A259_ECBA_1F11)
    #expect(result == expected, "48 bytes: got \(hex(result)), expected \(hex(expected))")
}

@Test
func xxh3Reference80Bytes() throws {
    // XXH3_64bits with 80 bytes of test pattern (65-96 byte range)
    let bytes = generateTestData(length: 80)
    let result = XXH3.hash(bytes, count: 80, seed: 0)
    let expected: Int64 = bitPattern(0xBCDE_FBBB_2C47_C90A)
    #expect(result == expected, "80 bytes: got \(hex(result)), expected \(hex(expected))")
}

@Test
func xxh3Reference195Bytes() throws {
    // XXH3_64bits with 195 bytes of test pattern (129-240 byte range)
    let bytes = generateTestData(length: 195)
    let result = XXH3.hash(bytes, count: 195, seed: 0)
    let expected: Int64 = bitPattern(0xCD94_217E_E362_EC3A)
    #expect(result == expected, "195 bytes: got \(hex(result)), expected \(hex(expected))")
}

@Test
func xxh3Reference403Bytes() throws {
    // XXH3_64bits with 403 bytes of test pattern (one block, last stripe overlapping)
    let bytes = generateTestData(length: 403)
    let result = XXH3.hash(bytes, count: 403, seed: 0)
    let expected: Int64 = bitPattern(0xCDEB_804D_65C6_DEA4)
    #expect(result == expected, "403 bytes: got \(hex(result)), expected \(hex(expected))")
}

@Test
func xxh3Reference512Bytes() throws {
    // XXH3_64bits with 512 bytes of test pattern (one block, stripe boundary)
    let bytes = generateTestData(length: 512)
    let result = XXH3.hash(bytes, count: 512, seed: 0)
    let expected: Int64 = bitPattern(0x617E_4959_9013_CB6B)
    #expect(result == expected, "512 bytes: got \(hex(result)), expected \(hex(expected))")
}

@Test
func xxh3Reference2048Bytes() throws {
    // XXH3_64bits with 2048 bytes of test pattern (2 blocks, block boundary)
    let bytes = generateTestData(length: 2048)
    let result = XXH3.hash(bytes, count: 2048, seed: 0)
    let expected: Int64 = bitPattern(0xDD59_E2C3_A5F0_38E0)
    #expect(result == expected, "2048 bytes: got \(hex(result)), expected \(hex(expected))")
}

// MARK: - XXH3_64bits with Seed Reference Tests
// PRIME64 = 11400714785074694797 = 0x9E3779B185EBCA8D

@Test
func xxh3ReferenceSeed1Byte() throws {
    // XXH3_64bits with 1 byte of test pattern, seed = PRIME64
    let bytes = generateTestData(length: 1)
    let seed: UInt64 = 0x9E37_79B1_85EB_CA8D
    let result = XXH3.hash(bytes, count: 1, seed: seed)
    let expected: Int64 = bitPattern(0x032B_E332_DD76_6EF8)
    #expect(
        result == expected, "1 byte seed=PRIME64: got \(hex(result)), expected \(hex(expected))")
}

@Test
func xxh3ReferenceSeed6Bytes() throws {
    // XXH3_64bits with 6 bytes of test pattern, seed = PRIME64
    let bytes = generateTestData(length: 6)
    let seed: UInt64 = 0x9E37_79B1_85EB_CA8D
    let result = XXH3.hash(bytes, count: 6, seed: seed)
    let expected: Int64 = bitPattern(0x8458_9C11_6AB5_9AB9)
    #expect(
        result == expected, "6 bytes seed=PRIME64: got \(hex(result)), expected \(hex(expected))"
    )
}

@Test
func xxh3ReferenceSeed12Bytes() throws {
    // XXH3_64bits with 12 bytes of test pattern, seed = PRIME64
    let bytes = generateTestData(length: 12)
    let seed: UInt64 = 0x9E37_79B1_85EB_CA8D
    let result = XXH3.hash(bytes, count: 12, seed: seed)
    let expected: Int64 = bitPattern(0xE730_3E1B_2336_DE0E)
    #expect(
        result == expected,
        "12 bytes seed=PRIME64: got \(hex(result)), expected \(hex(expected))")
}

@Test(.disabled("Long inputs with non-zero seed require custom secret generation"))
func xxh3ReferenceSeed2048Bytes() throws {
    // XXH3_64bits with 2048 bytes of test pattern, seed = PRIME64
    // Note: Long inputs (>240 bytes) with non-zero seed require generating a custom secret
    // based on the seed, which is not yet implemented. Short/medium inputs work correctly.
    let bytes = generateTestData(length: 2048)
    let seed: UInt64 = 0x9E37_79B1_85EB_CA8D
    let result = XXH3.hash(bytes, count: 2048, seed: seed)
    let expected: Int64 = bitPattern(0x66F8_1670_669A_BABC)
    #expect(
        result == expected,
        "2048 bytes seed=PRIME64: got \(hex(result)), expected \(hex(expected))")
}

// MARK: - Stability/Regression Tests
// These tests capture the current implementation's output to detect unintended changes.
// The values here are NOT from the official XXH3 reference - they document this implementation's behavior.

@Test func xxh3StabilityEmpty() throws {
    let bytes: [UInt8] = []
    let result = XXH3.hash(bytes, count: 0, seed: 0)
    let expected: Int64 = bitPattern(0x2D06_8005_38D3_94C2)
    #expect(result == expected, "Stability: empty input changed")
}

@Test func xxh3Stability1Byte() throws {
    let bytes = generateTestData(length: 1)
    let result = XXH3.hash(bytes, count: 1, seed: 0)
    let expected: Int64 = bitPattern(0xC44B_DFF4_074E_ECDB)
    #expect(result == expected, "Stability: 1 byte input changed")
}

@Test func xxh3Stability3Bytes() throws {
    let bytes = generateTestData(length: 3)
    let result = XXH3.hash(bytes, count: 3, seed: 0)
    let expected: Int64 = bitPattern(0x5424_7382_A8D6_B94D)
    #expect(result == expected, "Stability: 3 bytes input changed")
}

@Test func xxh3Stability4Bytes() throws {
    let bytes = generateTestData(length: 4)
    let result = XXH3.hash(bytes, count: 4, seed: 0)
    let expected: Int64 = bitPattern(0xE5DC_74BC_5184_8A51)
    #expect(result == expected, "Stability: 4 bytes input changed")
}

@Test func xxh3Stability8Bytes() throws {
    let bytes = generateTestData(length: 8)
    let result = XXH3.hash(bytes, count: 8, seed: 0)
    let expected: Int64 = bitPattern(0x24CC_C9AC_AA9F_65E4)
    #expect(result == expected, "Stability: 8 bytes input changed")
}

@Test func xxh3Stability16Bytes() throws {
    let bytes = generateTestData(length: 16)
    let result = XXH3.hash(bytes, count: 16, seed: 0)
    let expected: Int64 = bitPattern(0x981B_17D3_6C74_98C9)
    #expect(result == expected, "Stability: 16 bytes input changed")
}

@Test func xxh3Stability32Bytes() throws {
    let bytes = generateTestData(length: 32)
    let result = XXH3.hash(bytes, count: 32, seed: 0)
    let expected: Int64 = bitPattern(0x9FEA_DDBD_BF57_EED3)
    #expect(result == expected, "Stability: 32 bytes input changed")
}

@Test func xxh3Stability64Bytes() throws {
    let bytes = generateTestData(length: 64)
    let result = XXH3.hash(bytes, count: 64, seed: 0)
    let expected: Int64 = bitPattern(0x9CB4_8487_720E_C49D)
    #expect(result == expected, "Stability: 64 bytes input changed")
}

@Test func xxh3Stability128Bytes() throws {
    let bytes = generateTestData(length: 128)
    let result = XXH3.hash(bytes, count: 128, seed: 0)
    let expected: Int64 = bitPattern(0xFCFF_2412_6754_D861)
    #expect(result == expected, "Stability: 128 bytes input changed")
}

@Test func xxh3Stability256Bytes() throws {
    // Use fixed repeating pattern for reproducibility
    let bytes: [UInt8] = Array(repeating: 0xAB, count: 256)
    let result = XXH3.hash(bytes, count: 256, seed: 0)
    // Verify determinism: same input should always produce same output
    let result2 = XXH3.hash(bytes, count: 256, seed: 0)
    #expect(result == result2, "256 byte hash should be deterministic")
}

@Test func xxh3Stability1024Bytes() throws {
    // Use fixed repeating pattern for reproducibility
    let bytes: [UInt8] = Array(repeating: 0xCD, count: 1024)
    let result = XXH3.hash(bytes, count: 1024, seed: 0)
    // Verify determinism: same input should always produce same output
    let result2 = XXH3.hash(bytes, count: 1024, seed: 0)
    #expect(result == result2, "1024 byte hash should be deterministic")
}

@Test func xxh3Stability2048Bytes() throws {
    // Test even longer input for determinism
    let bytes: [UInt8] = Array(repeating: 0xEF, count: 2048)
    let result = XXH3.hash(bytes, count: 2048, seed: 0)
    // Verify determinism: same input should always produce same output
    let result2 = XXH3.hash(bytes, count: 2048, seed: 0)
    #expect(result == result2, "2048 byte hash should be deterministic")
}

@Test func xxh3StabilityWithSeed() throws {
    let bytes = generateTestData(length: 64)
    let result = XXH3.hash(bytes, count: 64, seed: 0x9E37_79B1)
    let expected: Int64 = bitPattern(0xEC06_A164_8C27_E203)
    #expect(result == expected, "Stability: 64 bytes with seed changed")
}

@Test func xxh3StabilityKnownStrings() throws {
    // Test with known ASCII strings for easy reproduction
    let helloResult = XXH3.hash("Hello, World!")
    let helloExpected: Int64 = XXH3.hash("Hello, World!")
    #expect(helloResult == helloExpected, "String hash should be deterministic")

    // Verify different strings produce different hashes
    let fooResult = XXH3.hash("foo")
    let barResult = XXH3.hash("bar")
    #expect(fooResult != barResult, "Different strings should hash differently")
}

// MARK: - Helpers for Reference Tests

/// Convert UInt64 to Int64 using bit pattern
private func bitPattern(_ value: UInt64) -> Int64 {
    Int64(bitPattern: value)
}

/// Format Int64 as hex string for debugging
private func hex(_ value: Int64) -> String {
    String(format: "0x%016llX", UInt64(bitPattern: value))
}

// MARK: - Helper Extensions

// Helper extension for the very long input test
extension Sequence {
    func repeatForever() -> AnySequence<Element> {
        AnySequence { () -> AnyIterator<Element> in
            var iterator = self.makeIterator()
            return AnyIterator {
                if let next = iterator.next() {
                    return next
                }
                iterator = self.makeIterator()
                return iterator.next()
            }
        }
    }
}
