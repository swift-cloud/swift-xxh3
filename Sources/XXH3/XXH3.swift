/// A fast, non-cryptographic hash function based on XXH3.
public enum XXH3 {
    // MARK: - Constants

    // XXH3 prime constants
    @usableFromInline static let prime32_1: UInt32 = 0x9E37_79B1
    @usableFromInline static let prime32_2: UInt32 = 0x85EB_CA77
    @usableFromInline static let prime32_3: UInt32 = 0xC2B2_AE3D

    @usableFromInline static let prime64_1: UInt64 = 0x9E37_79B1_85EB_CA87
    @usableFromInline static let prime64_2: UInt64 = 0xC2B2_AE3D_27D4_EB4F
    @usableFromInline static let prime64_3: UInt64 = 0x1656_67B1_9E37_79F9
    @usableFromInline static let prime64_4: UInt64 = 0x85EB_CA77_C2B2_AE63
    @usableFromInline static let prime64_5: UInt64 = 0x27D4_EB2F_1656_67C5

    // Stripe and block configuration
    @usableFromInline static let stripeLen = 64
    @usableFromInline static let accNb = 8
    @usableFromInline static let secretConsumeRate = 8
    @usableFromInline static let stripesPerBlock = 16  // (192 - 64) / 8
    @usableFromInline static let secretLastAccStart = 7  // XXH_SECRET_LASTACC_START
    @usableFromInline static let secretMergeAccsStart = 11
    @usableFromInline static let midSizeMax = 240
    @usableFromInline static let midSizeStartOffset = 3
    @usableFromInline static let midSizeLastOffset = 17

    // MARK: - Default Secret (192 bytes)

    @usableFromInline
    static let defaultSecret: [UInt8] = [
        0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad,
        0x1c,
        0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67,
        0x1f,
        0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72,
        0x21,
        0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26,
        0x4c,
        0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e,
        0xa3,
        0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac,
        0xd8,
        0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f,
        0x1d,
        0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73,
        0x64,
        0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63,
        0xeb,
        0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68,
        0x9e,
        0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31,
        0xce,
        0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40,
        0x7e,
    ]

    // MARK: - Public API

    /// Computes a fast 64-bit hash of the given bytes.
    /// - Parameters:
    ///   - bytes: The buffer to hash.
    ///   - seed: Optional seed value for the hash (default: 0).
    /// - Returns: A 64-bit hash value.
    @inlinable
    public static func hash(_ bytes: some Sequence<UInt8>, seed: UInt64 = 0) -> UInt64 {
        let data = Array(bytes)
        return hash(data, count: data.count, seed: seed)
    }

    /// Computes a fast 64-bit hash of the given byte array.
    /// - Parameters:
    ///   - bytes: The byte array to hash.
    ///   - count: The number of bytes to hash.
    ///   - seed: Optional seed value for the hash (default: 0).
    /// - Returns: A 64-bit hash value.
    @inlinable
    public static func hash(_ bytes: [UInt8], count: Int, seed: UInt64 = 0) -> UInt64 {
        bytes.withUnsafeBufferPointer { buffer in
            guard let baseAddress = buffer.baseAddress else {
                return hashLen0(seed: seed)
            }
            return hash(baseAddress, count: count, seed: seed)
        }
    }

    /// Computes a fast 64-bit hash of the given raw bytes.
    /// - Parameters:
    ///   - bytes: Pointer to the bytes to hash.
    ///   - count: The number of bytes to hash.
    ///   - seed: Optional seed value for the hash (default: 0).
    /// - Returns: A 64-bit hash value.
    @inlinable
    public static func hash(_ bytes: UnsafePointer<UInt8>, count: Int, seed: UInt64 = 0) -> UInt64 {
        defaultSecret.withUnsafeBufferPointer { secretBuffer in
            let secret = secretBuffer.baseAddress!
            return hashDispatch(bytes, count: count, seed: seed, secret: secret)
        }
    }

    /// Computes a fast 64-bit hash of a Hashable value.
    /// Uses the value's hash value as input.
    /// - Parameters:
    ///   - value: The hashable value to hash.
    ///   - seed: Optional seed value for the hash (default: 0).
    /// - Returns: A 64-bit hash value.
    @inlinable
    public static func hash<T: Hashable>(_ value: T, seed: UInt64 = 0) -> UInt64 {
        var hasher = Hasher()
        hasher.combine(value)
        let hashValue = hasher.finalize()
        return hash(hashValue, seed: seed)
    }

    /// Computes a fast 64-bit hash of a single integer.
    /// Optimized path for integer values.
    /// - Parameters:
    ///   - value: The integer value to hash.
    ///   - seed: Optional seed value for the hash (default: 0).
    /// - Returns: A 64-bit hash value.
    @inlinable
    public static func hash(_ value: Int, seed: UInt64 = 0) -> UInt64 {
        withUnsafeBytes(of: value.littleEndian) { buffer in
            let bytes = buffer.bindMemory(to: UInt8.self)
            return hash(bytes.baseAddress!, count: 8, seed: seed)
        }
    }

    /// Computes a fast 64-bit hash of a String.
    /// - Parameters:
    ///   - string: The string to hash.
    ///   - seed: Optional seed value for the hash (default: 0).
    /// - Returns: A 64-bit hash value.
    @inlinable
    public static func hash(_ string: String, seed: UInt64 = 0) -> UInt64 {
        var string = string
        return string.withUTF8 { buffer in
            guard let baseAddress = buffer.baseAddress else {
                return hashLen0(seed: seed)
            }
            return hash(baseAddress, count: buffer.count, seed: seed)
        }
    }

    // MARK: - Dispatcher

    @inlinable
    @inline(__always)
    static func hashDispatch(
        _ input: UnsafePointer<UInt8>,
        count: Int,
        seed: UInt64,
        secret: UnsafePointer<UInt8>
    ) -> UInt64 {
        if count <= 16 {
            return hashLen0to16(input, count: count, seed: seed, secret: secret)
        } else if count <= 128 {
            return hashLen17to128(input, count: count, seed: seed, secret: secret)
        } else if count <= midSizeMax {
            return hashLen129to240(input, count: count, seed: seed, secret: secret)
        } else {
            return hashLong(input, count: count, seed: seed, secret: secret)
        }
    }

    // MARK: - Length 0

    @inlinable
    @inline(__always)
    static func hashLen0(seed: UInt64) -> UInt64 {
        defaultSecret.withUnsafeBufferPointer { secretBuffer in
            let secret = secretBuffer.baseAddress!
            let secretLow = readLE64(secret.advanced(by: 56))
            let secretHigh = readLE64(secret.advanced(by: 64))
            return xxh64Avalanche(seed ^ secretLow ^ secretHigh)
        }
    }

    // MARK: - Length 1-16

    @inlinable
    @inline(__always)
    static func hashLen0to16(
        _ input: UnsafePointer<UInt8>,
        count: Int,
        seed: UInt64,
        secret: UnsafePointer<UInt8>
    ) -> UInt64 {
        if count == 0 {
            let secretLow = readLE64(secret.advanced(by: 56))
            let secretHigh = readLE64(secret.advanced(by: 64))
            return xxh64Avalanche(seed ^ secretLow ^ secretHigh)
        } else if count <= 3 {
            return hashLen1to3(input, count: count, seed: seed, secret: secret)
        } else if count <= 8 {
            return hashLen4to8(input, count: count, seed: seed, secret: secret)
        } else {
            return hashLen9to16(input, count: count, seed: seed, secret: secret)
        }
    }

    @inlinable
    @inline(__always)
    static func hashLen1to3(
        _ input: UnsafePointer<UInt8>,
        count: Int,
        seed: UInt64,
        secret: UnsafePointer<UInt8>
    ) -> UInt64 {
        let c1 = UInt32(input[0])
        let c2 = UInt32(input[count >> 1])
        let c3 = UInt32(input[count - 1])
        let combined = (c1 << 16) | (c2 << 24) | (c3 << 0) | (UInt32(count) << 8)
        let bitflip = UInt64(readLE32(secret) ^ readLE32(secret.advanced(by: 4))) &+ seed
        let keyed = UInt64(combined) ^ bitflip
        return xxh64Avalanche(keyed)
    }

    @inlinable
    @inline(__always)
    static func hashLen4to8(
        _ input: UnsafePointer<UInt8>,
        count: Int,
        seed: UInt64,
        secret: UnsafePointer<UInt8>
    ) -> UInt64 {
        // Important: seed must be modified by XORing with its byteswapped lower 32 bits shifted left
        let seed = seed ^ (UInt64(byteSwap32(UInt32(truncatingIfNeeded: seed))) << 32)
        let inputLo = UInt64(readLE32(input))
        let inputHi = UInt64(readLE32(input.advanced(by: count - 4)))
        let input64 = inputHi &+ (inputLo << 32)
        let bitflip = (readLE64(secret.advanced(by: 8)) ^ readLE64(secret.advanced(by: 16))) &- seed
        let keyed = input64 ^ bitflip
        return rrmxmx(keyed, len: UInt64(count))
    }

    @inlinable
    @inline(__always)
    static func hashLen9to16(
        _ input: UnsafePointer<UInt8>,
        count: Int,
        seed: UInt64,
        secret: UnsafePointer<UInt8>
    ) -> UInt64 {
        let bitflip1 =
            (readLE64(secret.advanced(by: 24)) ^ readLE64(secret.advanced(by: 32))) &+ seed
        let bitflip2 =
            (readLE64(secret.advanced(by: 40)) ^ readLE64(secret.advanced(by: 48))) &- seed
        let inputLow = readLE64(input) ^ bitflip1
        let inputHigh = readLE64(input.advanced(by: count - 8)) ^ bitflip2
        let acc =
            UInt64(count)
            &+ byteSwap64(inputLow) &+ inputHigh
            &+ mul128Fold64(inputLow, inputHigh)
        return avalanche(acc)
    }

    // MARK: - Length 17-128

    @inlinable
    static func hashLen17to128(
        _ input: UnsafePointer<UInt8>,
        count: Int,
        seed: UInt64,
        secret: UnsafePointer<UInt8>
    ) -> UInt64 {
        var acc = UInt64(count) &* prime64_1

        if count > 32 {
            if count > 64 {
                if count > 96 {
                    acc &+= mix16B(
                        input.advanced(by: 48), secret: secret.advanced(by: 96), seed: seed)
                    acc &+= mix16B(
                        input.advanced(by: count - 64), secret: secret.advanced(by: 112), seed: seed
                    )
                }
                acc &+= mix16B(input.advanced(by: 32), secret: secret.advanced(by: 64), seed: seed)
                acc &+= mix16B(
                    input.advanced(by: count - 48), secret: secret.advanced(by: 80), seed: seed)
            }
            acc &+= mix16B(input.advanced(by: 16), secret: secret.advanced(by: 32), seed: seed)
            acc &+= mix16B(
                input.advanced(by: count - 32), secret: secret.advanced(by: 48), seed: seed)
        }
        acc &+= mix16B(input, secret: secret, seed: seed)
        acc &+= mix16B(input.advanced(by: count - 16), secret: secret.advanced(by: 16), seed: seed)

        return avalanche(acc)
    }

    // MARK: - Length 129-240

    @inlinable
    static func hashLen129to240(
        _ input: UnsafePointer<UInt8>,
        count: Int,
        seed: UInt64,
        secret: UnsafePointer<UInt8>
    ) -> UInt64 {
        var acc = UInt64(count) &* prime64_1

        // First 128 bytes: 8 rounds of 16 bytes
        acc &+= mix16B(input.advanced(by: 0), secret: secret.advanced(by: 0), seed: seed)
        acc &+= mix16B(input.advanced(by: 16), secret: secret.advanced(by: 16), seed: seed)
        acc &+= mix16B(input.advanced(by: 32), secret: secret.advanced(by: 32), seed: seed)
        acc &+= mix16B(input.advanced(by: 48), secret: secret.advanced(by: 48), seed: seed)
        acc &+= mix16B(input.advanced(by: 64), secret: secret.advanced(by: 64), seed: seed)
        acc &+= mix16B(input.advanced(by: 80), secret: secret.advanced(by: 80), seed: seed)
        acc &+= mix16B(input.advanced(by: 96), secret: secret.advanced(by: 96), seed: seed)
        acc &+= mix16B(input.advanced(by: 112), secret: secret.advanced(by: 112), seed: seed)

        acc = avalanche(acc)

        // Middle section
        let nbRounds = (count - 128) / 16
        for i in 0..<nbRounds {
            acc &+= mix16B(
                input.advanced(by: 128 + i * 16),
                secret: secret.advanced(by: midSizeStartOffset + i * 16),
                seed: seed
            )
        }

        // Last 16 bytes
        acc &+= mix16B(
            input.advanced(by: count - 16),
            secret: secret.advanced(by: 136 - 17),  // 119
            seed: seed
        )

        return avalanche(acc)
    }

    // MARK: - Long Input (> 240 bytes)

    @inlinable
    static func hashLong(
        _ input: UnsafePointer<UInt8>,
        count: Int,
        seed: UInt64,
        secret: UnsafePointer<UInt8>
    ) -> UInt64 {
        var acc0 = UInt64(prime32_3)
        var acc1 = prime64_1
        var acc2 = prime64_2
        var acc3 = prime64_3
        var acc4 = prime64_4
        var acc5 = UInt64(prime32_2)
        var acc6 = prime64_5
        var acc7 = UInt64(prime32_1)

        // Process full blocks
        let nbStripes = (count - 1) / stripeLen
        let nbFullBlocks = nbStripes / stripesPerBlock
        let nbPartialStripes = nbStripes - (nbFullBlocks * stripesPerBlock)

        for block in 0..<nbFullBlocks {
            let blockStart = input.advanced(by: block * stripesPerBlock * stripeLen)

            for stripe in 0..<stripesPerBlock {
                let stripePtr = blockStart.advanced(by: stripe * stripeLen)
                let secretPtr = secret.advanced(by: stripe * secretConsumeRate)
                accumulate(
                    &acc0, &acc1, &acc2, &acc3, &acc4, &acc5, &acc6, &acc7,
                    stripe: stripePtr, secret: secretPtr)
            }

            // Scramble after each full block
            scrambleAcc(
                &acc0, &acc1, &acc2, &acc3, &acc4, &acc5, &acc6, &acc7,
                secret: secret.advanced(by: 192 - 64))
        }

        // Process remaining stripes
        let lastBlockStart = input.advanced(by: nbFullBlocks * stripesPerBlock * stripeLen)
        for stripe in 0..<nbPartialStripes {
            let stripePtr = lastBlockStart.advanced(by: stripe * stripeLen)
            let secretPtr = secret.advanced(by: stripe * secretConsumeRate)
            accumulate(
                &acc0, &acc1, &acc2, &acc3, &acc4, &acc5, &acc6, &acc7,
                stripe: stripePtr, secret: secretPtr)
        }

        // Process last stripe (may overlap with previous)
        // Secret offset is: secretSize - stripeLen - secretLastAccStart = 192 - 64 - 7 = 121
        let lastStripePtr = input.advanced(by: count - stripeLen)
        let lastStripeSecretOffset = 192 - stripeLen - secretLastAccStart  // 121
        accumulate(
            &acc0, &acc1, &acc2, &acc3, &acc4, &acc5, &acc6, &acc7,
            stripe: lastStripePtr, secret: secret.advanced(by: lastStripeSecretOffset))

        // Merge accumulators
        return mergeAccs(
            acc0, acc1, acc2, acc3, acc4, acc5, acc6, acc7,
            secret: secret.advanced(by: secretMergeAccsStart),
            start: UInt64(count) &* prime64_1)
    }

    // MARK: - Accumulator Operations

    @inlinable
    @inline(__always)
    static func accumulate(
        _ acc0: inout UInt64, _ acc1: inout UInt64, _ acc2: inout UInt64, _ acc3: inout UInt64,
        _ acc4: inout UInt64, _ acc5: inout UInt64, _ acc6: inout UInt64, _ acc7: inout UInt64,
        stripe: UnsafePointer<UInt8>,
        secret: UnsafePointer<UInt8>
    ) {
        // XXH3 scalar accumulation with lane swapping:
        // For each pair of lanes (0,1), (2,3), (4,5), (6,7):
        //   - data_val from lane N goes to acc[N ^ 1] (the adjacent lane)
        //   - the product stays in acc[N]
        // This is: xacc[lane ^ 1] += data_val; xacc[lane] += product

        // Read all data values first
        let data0 = readLE64(stripe.advanced(by: 0))
        let data1 = readLE64(stripe.advanced(by: 8))
        let data2 = readLE64(stripe.advanced(by: 16))
        let data3 = readLE64(stripe.advanced(by: 24))
        let data4 = readLE64(stripe.advanced(by: 32))
        let data5 = readLE64(stripe.advanced(by: 40))
        let data6 = readLE64(stripe.advanced(by: 48))
        let data7 = readLE64(stripe.advanced(by: 56))

        // Read secret values
        let key0 = readLE64(secret.advanced(by: 0))
        let key1 = readLE64(secret.advanced(by: 8))
        let key2 = readLE64(secret.advanced(by: 16))
        let key3 = readLE64(secret.advanced(by: 24))
        let key4 = readLE64(secret.advanced(by: 32))
        let key5 = readLE64(secret.advanced(by: 40))
        let key6 = readLE64(secret.advanced(by: 48))
        let key7 = readLE64(secret.advanced(by: 56))

        // Compute data_key = data ^ key for each lane
        let dataKey0 = data0 ^ key0
        let dataKey1 = data1 ^ key1
        let dataKey2 = data2 ^ key2
        let dataKey3 = data3 ^ key3
        let dataKey4 = data4 ^ key4
        let dataKey5 = data5 ^ key5
        let dataKey6 = data6 ^ key6
        let dataKey7 = data7 ^ key7

        // For each lane: acc[lane] += mult32to64(dataKey_lo, dataKey_hi)
        // For each lane: acc[lane ^ 1] += data_val
        // Combined: acc[lane] += data_from_adjacent + product_from_current

        // Lane 0: gets data1 (from lane 1) + product0
        acc0 = acc0 &+ data1 &+ mult32to64(dataKey0)
        // Lane 1: gets data0 (from lane 0) + product1
        acc1 = acc1 &+ data0 &+ mult32to64(dataKey1)
        // Lane 2: gets data3 (from lane 3) + product2
        acc2 = acc2 &+ data3 &+ mult32to64(dataKey2)
        // Lane 3: gets data2 (from lane 2) + product3
        acc3 = acc3 &+ data2 &+ mult32to64(dataKey3)
        // Lane 4: gets data5 (from lane 5) + product4
        acc4 = acc4 &+ data5 &+ mult32to64(dataKey4)
        // Lane 5: gets data4 (from lane 4) + product5
        acc5 = acc5 &+ data4 &+ mult32to64(dataKey5)
        // Lane 6: gets data7 (from lane 7) + product6
        acc6 = acc6 &+ data7 &+ mult32to64(dataKey6)
        // Lane 7: gets data6 (from lane 6) + product7
        acc7 = acc7 &+ data6 &+ mult32to64(dataKey7)
    }

    /// Multiply low 32 bits by high 32 bits of a 64-bit value
    @inlinable
    @inline(__always)
    static func mult32to64(_ x: UInt64) -> UInt64 {
        let lo = UInt64(UInt32(truncatingIfNeeded: x))
        let hi = UInt64(UInt32(truncatingIfNeeded: x >> 32))
        return lo &* hi
    }

    @inlinable
    @inline(__always)
    static func scrambleAcc(
        _ acc0: inout UInt64, _ acc1: inout UInt64, _ acc2: inout UInt64, _ acc3: inout UInt64,
        _ acc4: inout UInt64, _ acc5: inout UInt64, _ acc6: inout UInt64, _ acc7: inout UInt64,
        secret: UnsafePointer<UInt8>
    ) {
        acc0 = scrambleLane(acc0, secret: secret.advanced(by: 0))
        acc1 = scrambleLane(acc1, secret: secret.advanced(by: 8))
        acc2 = scrambleLane(acc2, secret: secret.advanced(by: 16))
        acc3 = scrambleLane(acc3, secret: secret.advanced(by: 24))
        acc4 = scrambleLane(acc4, secret: secret.advanced(by: 32))
        acc5 = scrambleLane(acc5, secret: secret.advanced(by: 40))
        acc6 = scrambleLane(acc6, secret: secret.advanced(by: 48))
        acc7 = scrambleLane(acc7, secret: secret.advanced(by: 56))
    }

    @inlinable
    @inline(__always)
    static func scrambleLane(_ acc: UInt64, secret: UnsafePointer<UInt8>) -> UInt64 {
        let xored = acc ^ (acc >> 47)
        let keyed = xored ^ readLE64(secret)
        return keyed &* UInt64(prime32_1)
    }

    @inlinable
    @inline(__always)
    static func mergeAccs(
        _ acc0: UInt64, _ acc1: UInt64, _ acc2: UInt64, _ acc3: UInt64,
        _ acc4: UInt64, _ acc5: UInt64, _ acc6: UInt64, _ acc7: UInt64,
        secret: UnsafePointer<UInt8>,
        start: UInt64
    ) -> UInt64 {
        var result = start

        result &+= mul128Fold64(
            acc0 ^ readLE64(secret.advanced(by: 0)), acc1 ^ readLE64(secret.advanced(by: 8)))
        result &+= mul128Fold64(
            acc2 ^ readLE64(secret.advanced(by: 16)), acc3 ^ readLE64(secret.advanced(by: 24)))
        result &+= mul128Fold64(
            acc4 ^ readLE64(secret.advanced(by: 32)), acc5 ^ readLE64(secret.advanced(by: 40)))
        result &+= mul128Fold64(
            acc6 ^ readLE64(secret.advanced(by: 48)), acc7 ^ readLE64(secret.advanced(by: 56)))

        return avalanche(result)
    }

    // MARK: - Mixing Functions

    @inlinable
    @inline(__always)
    static func mix16B(
        _ input: UnsafePointer<UInt8>,
        secret: UnsafePointer<UInt8>,
        seed: UInt64
    ) -> UInt64 {
        let inputLo = readLE64(input)
        let inputHi = readLE64(input.advanced(by: 8))
        return mul128Fold64(
            inputLo ^ (readLE64(secret) &+ seed),
            inputHi ^ (readLE64(secret.advanced(by: 8)) &- seed)
        )
    }

    /// 128-bit multiply, folded to 64-bit
    @inlinable
    @inline(__always)
    static func mul128Fold64(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
        let (high, low) = lhs.multipliedFullWidth(by: rhs)
        return low ^ high
    }

    // MARK: - Avalanche Functions

    /// XXH64 avalanche - used for short inputs (0-16 bytes) in XXH3
    /// This matches the reference XXH64_avalanche function
    @inlinable
    @inline(__always)
    static func xxh64Avalanche(_ h: UInt64) -> UInt64 {
        var h = h
        h ^= h >> 33
        h &*= prime64_2
        h ^= h >> 29
        h &*= prime64_3
        h ^= h >> 32
        return h
    }

    /// XXH3 avalanche - used for medium and long inputs
    @inlinable
    @inline(__always)
    static func avalanche64(_ h: UInt64) -> UInt64 {
        var h = h
        h ^= h >> 37
        h &*= 0x1656_6791_9E37_79F9  // PRIME_MX1
        h ^= h >> 32
        return h
    }

    @inlinable
    @inline(__always)
    static func avalanche(_ h: UInt64) -> UInt64 {
        var h = h
        h ^= h >> 37
        h &*= 0x1656_6791_9E37_79F9
        h ^= h >> 32
        return h
    }

    /// RRMXMX: Robust Rotate-Multiply-Xor-Multiply-Xor
    /// Strong avalanche for 4-8 byte inputs
    @inlinable
    @inline(__always)
    static func rrmxmx(_ h: UInt64, len: UInt64) -> UInt64 {
        var h = h ^ (rotl64(h, 49) ^ rotl64(h, 24))
        h &*= 0x9FB2_1C65_1E98_DF25
        h ^= (h >> 35) &+ len
        h &*= 0x9FB2_1C65_1E98_DF25
        return h ^ (h >> 28)
    }

    // MARK: - Utility Functions

    @inlinable
    @inline(__always)
    static func rotl64(_ x: UInt64, _ r: UInt64) -> UInt64 {
        (x << r) | (x >> (64 - r))
    }

    @inlinable
    @inline(__always)
    static func byteSwap64(_ x: UInt64) -> UInt64 {
        return x.byteSwapped
    }

    @inlinable
    @inline(__always)
    static func byteSwap32(_ x: UInt32) -> UInt32 {
        return x.byteSwapped
    }

    @inlinable
    @inline(__always)
    static func readLE64(_ ptr: UnsafePointer<UInt8>) -> UInt64 {
        UnsafeRawPointer(ptr).loadUnaligned(as: UInt64.self).littleEndian
    }

    @inlinable
    @inline(__always)
    static func readLE32(_ ptr: UnsafePointer<UInt8>) -> UInt32 {
        UnsafeRawPointer(ptr).loadUnaligned(as: UInt32.self).littleEndian
    }
}
