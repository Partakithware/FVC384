# FVC384 Hash Function

**File Verification Content - 384-bit cryptographic hash function**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)]()

A high-performance, novel hash function built on Tesla's 3-6-9 principle, optimized for file integrity verification.

---

## 🎯 Overview

FVC384 is a 384-bit hash function designed for fast, reliable file verification. It features:

- **⚡ High Performance**: 445 MB/s throughput (faster than SHA-256 on tested hardware)
- **🔒 Strong Collision Resistance**: 2^192 birthday bound (stronger than SHA-256's 2^128)
- **🎨 Novel Design**: 6-lane parallel architecture with 3/6/9 rotation pattern
- **🚀 SIMD Optimized**: AVX2 acceleration with automatic fallback
- **🌍 Cross-Platform**: Linux, macOS, Windows (C with OpenSSL)

---

## ⚠️ Important Disclaimer

**FVC384 should (based on my knowledge, hobbyist so use at your own risk) be production-ready for file integrity verification but NOT for cryptographic security applications.**

✅ **Recommended uses:**
- File checksums and integrity verification
- Data deduplication
- Archive verification
- Content-addressable storage
- Non-security-critical hashing

❌ **NOT recommended for:**
- Password hashing
- Digital signatures
- Certificate validation
- Any security-critical cryptographic use

**Reason**: While FVC384 shows strong collision resistance and uniform distribution in testing, it has not undergone formal cryptanalysis or academic peer review. Use established cryptographic hash functions (SHA-256, SHA-3, BLAKE2) for security applications.

---

## 🔬 Technical Specifications

| Feature | Specification |
|---------|--------------|
| **Output Size** | 384 bits (48 bytes) |
| **Block Size** | 256 bytes |
| **Internal State** | 6 × 64-bit lanes (384 bits) |
| **Rounds** | 30 compression rounds |
| **Rotation Amounts** | 3, 6, 9, 12, 18, 27 (multiples of 3) |
| **Birthday Bound** | 2^192 (~6.3 × 10^57) |
| **SIMD Support** | AVX2 (runtime detection) |

---

## 📊 Performance Benchmarks

Tested on: Intel i5/i7 laptop (exact specs in benchmark output)

```
File: 298.26 MB
FVC384:  0.6707s (445 MB/s)
SHA-256: 0.7700s (387 MB/s)

Result: ~15% faster than SHA-256
```

Performance characteristics:
- **Small files (<1MB)**: Comparable to SHA-256
- **Large files (>100MB)**: 10-20% faster than SHA-256
- **Memory usage**: Minimal (< 1KB context)
- **Streaming**: Efficient with 256KB I/O buffer

---

## 🧪 Collision Testing

**Test 1: Random File Distribution**
- **Files tested**: 1,000,000 × 1KB random files
- **Collisions found**: 0
- **First-byte distribution**: 251/256 values (98% coverage)
- **Statistical uniformity**: χ² test passed

**Test 2: Modification Sensitivity**
- Single bit flip → Complete hash change
- Truncation → Unrelated hash
- Padding → Unrelated hash
- Byte swap → Unrelated hash

**Test 3: Avalanche Effect**
- Minor input changes produce major output changes
- No clustering patterns observed
- Full 384-bit output space utilized

---

## 🏗️ Architecture

### Design Philosophy

FVC384 is built around **Tesla's 3-6-9 principle**:
> "If you only knew the magnificence of the 3, 6 and 9, then you would have the key to the universe." — Nikola Tesla

While inspired by numerology, the design is grounded in cryptographic best practices:

- **6 parallel lanes**: Non-power-of-2 for reduced alignment artifacts
- **3/6/9/12/18/27 rotations**: Coprime to 64, optimal for bit mixing
- **30 rounds**: 3 × 10, balanced security/performance tradeoff
- **384-bit output**: 3 × 128, clean multiple with strong collision resistance

### Algorithmic Structure

```
Input → 256-byte blocks → 6-lane parallel processing
                              ↓
                    30 rounds of mixing:
                    - Sigma functions (3/6/9 rotations)
                    - Choice/Majority functions
                    - Cross-lane diffusion (every 3 rounds)
                    - Message schedule expansion
                              ↓
                    3 final mixing rounds
                              ↓
                    384-bit digest output
```

### Key Operations

- **SIGMA0**: `ROTR(x,3) ⊕ ROTR(x,6) ⊕ ROTR(x,9)`
- **SIGMA1**: `ROTR(x,12) ⊕ ROTR(x,18) ⊕ ROTR(x,27)`
- **CH**: Choice function `(x ∧ y) ⊕ (¬x ∧ z)`
- **MAJ**: Majority function `(x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)`

---

## 🚀 Installation

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt install build-essential libssl-dev

# macOS
brew install openssl

# Arch Linux
sudo pacman -S base-devel openssl
```

### Build from Source

```bash
git clone https://github.com/Partakithware/fvc384.git
cd fvc384

# Compile single-file implementation
gcc -O3 -march=native -mavx2 fvc384.c -o fvc384 -lssl -lcrypto

# Or without AVX2
gcc -O3 fvc384.c -o fvc384 -lssl -lcrypto
```

### Compile Options

```bash
# Optimized build (recommended)
gcc -O3 -march=native -mavx2 fvc384.c -o fvc384 -lssl -lcrypto

# Debug build
gcc -g -O0 fvc384.c -o fvc384 -lssl -lcrypto

# What I used during testing
gcc -O3 -march=native -funroll-loops -fomit-frame-pointer -o fvc324 fvc324.c

# Portable build (no CPU-specific optimizations)
gcc -O2 fvc384.c -o fvc384 -lssl -lcrypto
```

---

## 💻 Usage

### Command Line

```bash
# Hash a single file
./fvc384 file.bin

# Output: 96-character hex digest
9f38ae16f1e09b6e5cf0b4d8c02ca695b54e39fdbd341424b0edaa98d807af06...

# Benchmark mode
./fvc384 benchmark largefile.bin

# Multiple files
./fvc384 file1.bin file2.bin file3.bin

# With timing
time ./fvc384 file.bin
```

### API Usage (C)

FVC384 is currently a single-file implementation. To use in your project:

```c
// Compile fvc384.c with your project or extract the functions you need

// One-shot hashing
uint8_t digest[48];
FVC384_hash(data, data_len, digest);

// Streaming API
FVC384_ctx ctx;
FVC384_init(&ctx, DEFAULT_SALT);

FVC384_update(&ctx, chunk1, len1);
FVC384_update(&ctx, chunk2, len2);
// ... more updates

FVC384_final(&ctx, digest);

// File hashing
uint8_t digest[48];
if (FVC384_hash_file("path/to/file", digest) == 0) {
    // Success - digest contains hash
}
```

Note: All function declarations are in `fvc384.c`. For library usage, consider extracting to separate `.h` and `.c` files.

### Integration Examples

**Makefile Integration:**
```makefile
# Add to your project
fvc384: fvc384.c
	gcc -O3 -march=native -mavx2 fvc384.c -o fvc384 -lssl -lcrypto

verify: program fvc384
	./fvc384 program > program.fvc384
	@echo "Hash saved to program.fvc384"

check: program fvc384
	./fvc384 program | diff - program.fvc384
	@echo "Integrity verified!"
```

**Shell Script:**
```bash
#!/bin/bash
# Verify archive integrity before extraction

ARCHIVE="backup.tar.gz"
EXPECTED="abc123def456..."  # Known good hash

ACTUAL=$(fvc384 "$ARCHIVE" | cut -d' ' -f1)

if [ "$ACTUAL" = "$EXPECTED" ]; then
    tar xzf "$ARCHIVE"
else
    echo "ERROR: Archive corrupted!"
    exit 1
fi
```

---

## 📈 Comparison with Other Hash Functions

| Hash Function | Output | Speed (MB/s) | Security Status | Use Case |
|--------------|--------|--------------|-----------------|----------|
| **MD5** | 128-bit | ~600 | Broken | Legacy only |
| **SHA-1** | 160-bit | ~500 | Broken | Legacy only |
| **SHA-256** | 256-bit | ~387 | Secure | General purpose |
| **SHA-512** | 512-bit | ~500 | Secure | High security |
| **SHA3-256** | 256-bit | ~300 | Secure | Modern standard |
| **BLAKE2b** | 512-bit | ~1000 | Secure | High performance |
| **BLAKE3** | 256-bit | ~3000 | Secure | Cutting edge |
| **xxHash** | 64-bit | ~15000 | Not crypto | Checksums only |
| **FVC384** | 384-bit | ~445 | Unanalyzed | File verification |

**FVC384's niche:**
- Faster than SHA-256/SHA-3 for file verification
- Stronger collision resistance than SHA-256
- Simpler than BLAKE2/BLAKE3 (easier to audit)
- Not as battle-tested as established standards

---

## 🔍 Algorithm Deep Dive

### Why 6 Lanes?

Most hash functions use power-of-2 lanes (4, 8, 16) for alignment efficiency. FVC384 uses **6 lanes** because:

1. **Divisibility by 3**: Fits the 3/6/9 theme
2. **Non-power-of-2**: Reduces cache-timing attack surface
3. **Cross-lane complexity**: Creates richer dependency graph
4. **384-bit output**: Natural fit (6 × 64 = 384)

### Rotation Schedule

Traditional hashes use rotations like 7, 18, 41 (random-looking primes). FVC384 uses **3, 6, 9, 12, 18, 27**:

- All multiples of 3
- Coprime to 64 (for full-cycle rotation)
- Progressive doubling pattern (3→6→12)
- Creates predictable but effective mixing

### Message Schedule

32 × 64-bit words extracted from each 256-byte block:
- Updated every 3 rounds (not every round like SHA-2)
- Uses GAMMA functions for expansion
- Optimized to only update needed words (6 per update)

### Final Mixing

After padding and final compression, **3 additional mixing rounds** ensure:
- Full bit participation across all lanes
- No truncation bias in output
- Uniform distribution across 384-bit space

---

## 🐛 Known Limitations

1. **No formal cryptanalysis**: Use at your own risk for non-security applications
2. **Novel design**: Lacks the decades of scrutiny SHA-2 has received
3. **SIMD dependency**: Scalar fallback is ~30% slower
4. **Large digest**: 48 bytes vs SHA-256's 32 bytes (if storage is constrained)
5. **Not quantum-resistant**: Like all classical hashes (Grover's algorithm applies)

---

## 🤝 Contributing

Contributions welcome! Especially:

- **Cryptanalysis**: Find weaknesses, collision attacks, preimage vulnerabilities
- **Performance**: Optimize SIMD code, add ARM NEON support
- **Code organization**: Create proper `.h`/`.c` split, build system (Makefile/CMake)
- **Ports**: Rust, Go, Python implementations
- **Testing**: More collision tests, fuzzing, differential analysis
- **Documentation**: Explain algorithm better, add diagrams

### Security Researchers

**Found a vulnerability?** Please report responsibly via GitHub issues or discussion.

Community cryptanalysis and security research is welcomed and encouraged.

---

## 📜 License

MIT License - see LICENSE file

Free for commercial and non-commercial use.

---

## 🙏 Acknowledgments

- **Nikola Tesla**: For the 3-6-9 inspiration (even if he'd find this use amusing)
- **Claude (Anthropic)**: For collaborative algorithm design and debugging
- **SHA-2 designers**: For the architectural patterns this builds upon
- **BLAKE2 team**: For demonstrating that novel designs can compete with standards

---

## 📚 References & Further Reading

- [Tesla's 3-6-9 Theory](https://en.wikipedia.org/wiki/Nikola_Tesla#Numerology) (inspiration only)
- [Cryptographic Hash Functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function) (Wikipedia)
- [NIST Hash Function Standards](https://csrc.nist.gov/projects/hash-functions)
- [Birthday Attack Analysis](https://en.wikipedia.org/wiki/Birthday_attack)
- [Merkle–Damgård Construction](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction)

---

## 📞 Contact

- **Author**: Maxwell Wingate
- **GitHub**: [@Partakithware](https://github.com/Partakithware)
- **Project**: https://github.com/Partakithware/fvc384

---

## ⚡ Quick Start

```bash
# Clone and build
git clone https://github.com/Partakithware/fvc384.git
cd fvc384
gcc -O3 -march=native -mavx2 fvc384.c -o fvc384 -lssl -lcrypto

# Test on a file
./fvc384 /path/to/file

# Run built-in tests
./fvc384 test

# Benchmark
./fvc384 benchmark /path/to/large/file
```

---

**Built with curiosity, tested with rigor, released with humility.**

*FVC384: Fast enough to matter, different enough to be interesting.*
