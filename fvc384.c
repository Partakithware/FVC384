#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <cpuid.h>
#include <immintrin.h>

// FVC384: 6-lane parallel hash with 3/6/9 rotation pattern
// Output: 324 bits (6 lanes × 54 bits effective)

#define FVC384_LANES 6
#define FVC384_ROUNDS 30   // 3^4, perfectly divisible by 3, balanced speed/security
#define FVC384_BLOCK_SIZE 256  // bytes - larger blocks for better throughput

typedef struct {
    uint64_t state[FVC384_LANES];  // 6 lanes of 64-bit state
    uint64_t salt[FVC384_LANES];
    uint8_t buffer[FVC384_BLOCK_SIZE];
    uint64_t total_len;
    size_t buffer_len;
} FVC384_ctx;

// Initial hash values (derived from fractional parts of cube roots of first 6 primes)
static const uint64_t IV[FVC384_LANES] = {
    0x6a09e667f3bcc908ULL,  // sqrt(2)
    0xbb67ae8584caa73bULL,  // sqrt(3)
    0x3c6ef372fe94f82bULL,  // sqrt(5)
    0xa54ff53a5f1d36f1ULL,  // sqrt(7)
    0x510e527fade682d1ULL,  // sqrt(11)
    0x9b05688c2b3e6c1fULL   // sqrt(13)
};

static const uint64_t DEFAULT_SALT[FVC384_LANES] = {
    0x243f6a8885a308d3ULL,
    0x13198a2e03707344ULL,
    0xa4093822299f31d0ULL,
    0x082efa98ec4e6c89ULL,
    0x452821e638d01377ULL,
    0xbe5466cf34e90c6cULL
};

static const uint64_t DOMAIN_CONST[FVC384_LANES] = {
    0x6a09e667f3bcc908ULL,  // sqrt(2)
    0xbb67ae8584caa73bULL,  // sqrt(3)
    0x3c6ef372fe94f82bULL,  // sqrt(5)
    0xa54ff53a5f1d36f1ULL,  // sqrt(7)
    0x510e527fade682d1ULL,  // sqrt(11)
    0x9b05688c2b3e6c1fULL   // sqrt(13)
};

// CPU feature detection
static int has_avx2 = -1;

static int detect_avx2() {
    if (has_avx2 != -1) return has_avx2;
    
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        int has_avx = (ecx & bit_AVX) != 0;
        int has_osxsave = (ecx & bit_OSXSAVE) != 0;
        
        if (has_avx && has_osxsave) {
            if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
                has_avx2 = (ebx & bit_AVX2) != 0;
                return has_avx2;
            }
        }
    }
    has_avx2 = 0;
    return 0;
}

// Rotation macros
#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROTL(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

// Tesla-inspired rotation amounts: 3, 6, 9, 12, 18, 27
#define R3(x)  ROTR(x, 3)
#define R6(x)  ROTR(x, 6)
#define R9(x)  ROTR(x, 9)
#define R12(x) ROTR(x, 12)
#define R18(x) ROTR(x, 18)
#define R27(x) ROTR(x, 27)

// Non-linear mixing functions
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

// Sigma functions using our 3/6/9 rotations
#define SIGMA0(x) (R3(x) ^ R6(x) ^ R9(x))
#define SIGMA1(x) (R12(x) ^ R18(x) ^ R27(x))

// Message schedule mixing
#define GAMMA0(x) (R6(x) ^ R9(x) ^ ((x) >> 3))
#define GAMMA1(x) (R18(x) ^ R27(x) ^ ((x) >> 6))

// AVX2 SIMD rotation helpers
static inline __m256i rotr_epi64(__m256i x, int n) {
    return _mm256_or_si256(_mm256_srli_epi64(x, n), _mm256_slli_epi64(x, 64 - n));
}

static inline __m256i rotl_epi64(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi64(x, n), _mm256_srli_epi64(x, 64 - n));
}

void FVC384_init(FVC384_ctx *ctx, const uint64_t salt[FVC384_LANES]) {
    for (int i = 0; i < FVC384_LANES; i++) {
        ctx->salt[i]  = salt[i];
        ctx->state[i] = IV[i] ^ ROTL(salt[i], (i * 11) & 63);
    }

    ctx->total_len  = 0;
    ctx->buffer_len = 0;
    memset(ctx->buffer, 0, FVC384_BLOCK_SIZE);
}

// Scalar version of transform (fallback)
static void FVC384_transform_scalar(FVC384_ctx *ctx, const uint8_t *block) {
    uint64_t W[32];  // 32 × 64-bit words from 256-byte block
    uint64_t lanes[FVC384_LANES];
    
    for (int i = 0; i < FVC384_LANES; i++) {
        lanes[i] = ctx->state[i];
    }
    
    // Prepare message schedule (32 × 64-bit words from 256-byte block)
    for (int i = 0; i < 32; i++) {
        W[i] = ((uint64_t)block[i*8 + 0] << 56) |
               ((uint64_t)block[i*8 + 1] << 48) |
               ((uint64_t)block[i*8 + 2] << 40) |
               ((uint64_t)block[i*8 + 3] << 32) |
               ((uint64_t)block[i*8 + 4] << 24) |
               ((uint64_t)block[i*8 + 5] << 16) |
               ((uint64_t)block[i*8 + 6] << 8)  |
               ((uint64_t)block[i*8 + 7]);
    }
    
    for (int round = 0; round < FVC384_ROUNDS; round++) {
        uint64_t temp[FVC384_LANES];
        
        for (int lane = 0; lane < FVC384_LANES; lane++) {
            int w_idx = (round + lane) % 32;  // Now mod 32 instead of 16
            uint64_t t1 = lanes[lane] + SIGMA1(lanes[(lane+1) % FVC384_LANES]) + 
                         CH(lanes[lane], lanes[(lane+2) % FVC384_LANES], lanes[(lane+3) % FVC384_LANES]) +
                         W[w_idx] + round;
            
            uint64_t t2 = SIGMA0(lanes[lane]) + 
                         MAJ(lanes[lane], lanes[(lane+4) % FVC384_LANES], lanes[(lane+5) % FVC384_LANES]);
            
            temp[lane] = t1 + t2;
        }
        
        if ((round + 1) % 3 == 0) {
            for (int lane = 0; lane < FVC384_LANES; lane++) {
                temp[lane] ^= ROTL(temp[(lane + 2) % FVC384_LANES], 3);
                temp[lane] += ROTR(temp[(lane + 4) % FVC384_LANES], 6);
            }
        }
        
        for (int lane = 0; lane < FVC384_LANES; lane++) {
            lanes[lane] = temp[lane];
        }
        
        // Update message schedule with larger array
        if ((round + 1) % 3 == 0 && round < FVC384_ROUNDS - 3) {
            // OPTIMIZED: Only update next 6 words we'll use
            for (int i = 0; i < 6; i++) {
                int idx = ((round / 3 + 2) * 6 + i) % 32;
                W[idx] = GAMMA1(W[idx]) + W[(idx + 17) % 32] + GAMMA0(W[(idx + 1) % 32]);
            }
        }
    }
    
    for (int i = 0; i < FVC384_LANES; i++) {
        ctx->state[i] += lanes[i];
    }
}

// AVX2 SIMD version - optimized
static void FVC384_transform_avx2(FVC384_ctx *ctx, const uint8_t *block) {
    uint64_t W[32] __attribute__((aligned(32)));
    
    // Prepare message schedule
    for (int i = 0; i < 32; i++) {
        W[i] = ((uint64_t)block[i*8 + 0] << 56) |
               ((uint64_t)block[i*8 + 1] << 48) |
               ((uint64_t)block[i*8 + 2] << 40) |
               ((uint64_t)block[i*8 + 3] << 32) |
               ((uint64_t)block[i*8 + 4] << 24) |
               ((uint64_t)block[i*8 + 5] << 16) |
               ((uint64_t)block[i*8 + 6] << 8)  |
               ((uint64_t)block[i*8 + 7]);
    }
    
    __m256i v0 = _mm256_set_epi64x(ctx->state[3], ctx->state[2], ctx->state[1], ctx->state[0]);
    __m256i v1 = _mm256_set_epi64x(ctx->state[1], ctx->state[0], ctx->state[5], ctx->state[4]);
    
    for (int round = 0; round < FVC384_ROUNDS; round++) {
        // Extract lanes once per round
        uint64_t lanes[8] __attribute__((aligned(32)));
        _mm256_storeu_si256((__m256i*)&lanes[0], v0);
        _mm256_storeu_si256((__m256i*)&lanes[4], v1);
        
        __m256i w0 = _mm256_set_epi64x(W[(round+3)%32], W[(round+2)%32], W[(round+1)%32], W[(round+0)%32]);
        __m256i w1 = _mm256_set_epi64x(W[(round+5)%32], W[(round+4)%32], W[(round+5)%32], W[(round+4)%32]);
        __m256i round_const = _mm256_set1_epi64x(round);
        
        __m256i v0_plus1 = _mm256_set_epi64x(lanes[4], lanes[3], lanes[2], lanes[1]);
        __m256i v0_plus2 = _mm256_set_epi64x(lanes[5], lanes[4], lanes[3], lanes[2]);
        __m256i v0_plus3 = _mm256_set_epi64x(lanes[0], lanes[5], lanes[4], lanes[3]);
        __m256i v0_plus4 = _mm256_set_epi64x(lanes[1], lanes[0], lanes[5], lanes[4]);
        __m256i v0_plus5 = _mm256_set_epi64x(lanes[2], lanes[1], lanes[0], lanes[5]);
        
        __m256i s1_0 = _mm256_xor_si256(rotr_epi64(v0_plus1, 12), _mm256_xor_si256(rotr_epi64(v0_plus1, 18), rotr_epi64(v0_plus1, 27)));
        __m256i ch_0 = _mm256_xor_si256(_mm256_and_si256(v0, v0_plus2), _mm256_andnot_si256(v0, v0_plus3));
        __m256i t1_0 = _mm256_add_epi64(_mm256_add_epi64(_mm256_add_epi64(_mm256_add_epi64(v0, s1_0), ch_0), w0), round_const);
        __m256i s0_0 = _mm256_xor_si256(rotr_epi64(v0, 3), _mm256_xor_si256(rotr_epi64(v0, 6), rotr_epi64(v0, 9)));
        __m256i maj_0 = _mm256_xor_si256(_mm256_and_si256(v0, v0_plus4), _mm256_xor_si256(_mm256_and_si256(v0, v0_plus5), _mm256_and_si256(v0_plus4, v0_plus5)));
        __m256i temp0 = _mm256_add_epi64(t1_0, _mm256_add_epi64(s0_0, maj_0));
        
        __m256i v1_plus1 = _mm256_set_epi64x(lanes[2], lanes[1], lanes[0], lanes[5]);
        __m256i v1_plus2 = _mm256_set_epi64x(lanes[3], lanes[2], lanes[1], lanes[0]);
        __m256i v1_plus3 = _mm256_set_epi64x(lanes[4], lanes[3], lanes[2], lanes[1]);
        __m256i v1_plus4 = _mm256_set_epi64x(lanes[5], lanes[4], lanes[3], lanes[2]);
        __m256i v1_plus5 = _mm256_set_epi64x(lanes[0], lanes[5], lanes[4], lanes[3]);
        
        __m256i s1_1 = _mm256_xor_si256(rotr_epi64(v1_plus1, 12), _mm256_xor_si256(rotr_epi64(v1_plus1, 18), rotr_epi64(v1_plus1, 27)));
        __m256i ch_1 = _mm256_xor_si256(_mm256_and_si256(v1, v1_plus2), _mm256_andnot_si256(v1, v1_plus3));
        __m256i t1_1 = _mm256_add_epi64(_mm256_add_epi64(_mm256_add_epi64(_mm256_add_epi64(v1, s1_1), ch_1), w1), round_const);
        __m256i s0_1 = _mm256_xor_si256(rotr_epi64(v1, 3), _mm256_xor_si256(rotr_epi64(v1, 6), rotr_epi64(v1, 9)));
        __m256i maj_1 = _mm256_xor_si256(_mm256_and_si256(v1, v1_plus4), _mm256_xor_si256(_mm256_and_si256(v1, v1_plus5), _mm256_and_si256(v1_plus4, v1_plus5)));
        __m256i temp1 = _mm256_add_epi64(t1_1, _mm256_add_epi64(s0_1, maj_1));
        
        if ((round + 1) % 3 == 0) {
            uint64_t temp[8] __attribute__((aligned(32)));
            _mm256_storeu_si256((__m256i*)&temp[0], temp0);
            _mm256_storeu_si256((__m256i*)&temp[4], temp1);
            
            __m256i temp_p2_v0 = _mm256_set_epi64x(temp[5], temp[4], temp[3], temp[2]);
            __m256i temp_p4_v0 = _mm256_set_epi64x(temp[1], temp[0], temp[5], temp[4]);
            __m256i temp_p2_v1 = _mm256_set_epi64x(0, 0, temp[1], temp[0]);
            __m256i temp_p4_v1 = _mm256_set_epi64x(0, 0, temp[3], temp[2]);
            
            temp0 = _mm256_add_epi64(_mm256_xor_si256(temp0, rotl_epi64(temp_p2_v0, 3)), rotr_epi64(temp_p4_v0, 6));
            temp1 = _mm256_add_epi64(_mm256_xor_si256(temp1, rotl_epi64(temp_p2_v1, 3)), rotr_epi64(temp_p4_v1, 6));
        }
        
        v0 = temp0;
        v1 = temp1;
        
        // OPTIMIZED: Only update next 6 W words
        if ((round + 1) % 3 == 0 && round < FVC384_ROUNDS - 3) {
            for (int i = 0; i < 6; i++) {
                int idx = ((round / 3 + 2) * 6 + i) % 32;
                W[idx] = GAMMA1(W[idx]) + W[(idx + 17) % 32] + GAMMA0(W[(idx + 1) % 32]);
            }
        }
    }
    
    uint64_t final_lanes[8] __attribute__((aligned(32)));
    _mm256_storeu_si256((__m256i*)&final_lanes[0], v0);
    _mm256_storeu_si256((__m256i*)&final_lanes[4], v1);
    
    for (int i = 0; i < 6; i++) {
        ctx->state[i] += final_lanes[i];
    }
}

static void FVC384_transform(FVC384_ctx *ctx, const uint8_t *block) {
    if (detect_avx2()) {
        FVC384_transform_avx2(ctx, block);
    } else {
        FVC384_transform_scalar(ctx, block);
    }
}

void FVC384_update(FVC384_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total_len += len;
    
    while (len > 0) {
        size_t to_copy = FVC384_BLOCK_SIZE - ctx->buffer_len;
        if (to_copy > len) to_copy = len;
        
        memcpy(ctx->buffer + ctx->buffer_len, data, to_copy);
        ctx->buffer_len += to_copy;
        data += to_copy;
        len -= to_copy;
        
        if (ctx->buffer_len == FVC384_BLOCK_SIZE) {
            FVC384_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

void FVC384_final(FVC384_ctx *ctx, uint8_t *digest) {
    size_t pad_len = FVC384_BLOCK_SIZE - ctx->buffer_len;
    if (pad_len < 9) pad_len += FVC384_BLOCK_SIZE;
    
    uint8_t padding[FVC384_BLOCK_SIZE * 2] = {0};
    padding[0] = 0x80;
    
    uint64_t bit_len = ctx->total_len * 8;
    for (int i = 0; i < 8; i++) {
        padding[pad_len - 8 + i] = (bit_len >> (56 - i*8)) & 0xFF;
    }
    
    FVC384_update(ctx, padding, pad_len);
    
    // Final mixing round to ensure full bit participation
    for (int mix = 0; mix < 3; mix++) {
        for (int i = 0; i < FVC384_LANES; i++) {
            ctx->state[i] ^= ROTL(ctx->state[(i+1) % FVC384_LANES], 13);
            ctx->state[i] += ROTR(ctx->state[(i+3) % FVC384_LANES], 29);
            ctx->state[i] ^= ctx->state[(i+5) % FVC384_LANES];
        }
    }
    
    // Extract 48 bytes (384 bits) - 8 bytes per lane, all 6 lanes
    for (int i = 0; i < FVC384_LANES; i++) {
        uint64_t lane = ctx->state[i];  // No masking - use full 64 bits
        
        for (int j = 0; j < 8; j++) {
            digest[i * 8 + j] = (lane >> (56 - j*8)) & 0xFF;
        }
    }
}

void FVC384_hash(const uint8_t *data, size_t len, uint8_t *digest) {
    FVC384_ctx ctx;
    FVC384_init(&ctx, DEFAULT_SALT);
    FVC384_update(&ctx, data, len);
    FVC384_final(&ctx, digest);
}

int FVC384_hash_file(const char *filename, uint8_t *digest) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        return -1;
    }
    
    // Optimize I/O buffering - 1MB buffer
    setvbuf(f, NULL, _IOFBF, 1 << 20);
    
    FVC384_ctx ctx;
    FVC384_init(&ctx, DEFAULT_SALT);
    
    // Larger read buffer for better I/O throughput
    uint8_t buffer[262144];  // 256KB buffer instead of 8KB
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        FVC384_update(&ctx, buffer, bytes_read);
    }
    
    fclose(f);
    FVC384_final(&ctx, digest);
    return 0;
}

long get_file_size(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size;
    }
    return -1;
}

void format_size(long bytes, char *output) {
    if (bytes < 1024) {
        sprintf(output, "%ld B", bytes);
    } else if (bytes < 1024 * 1024) {
        sprintf(output, "%.2f KB", bytes / 1024.0);
    } else if (bytes < 1024 * 1024 * 1024) {
        sprintf(output, "%.2f MB", bytes / (1024.0 * 1024.0));
    } else {
        sprintf(output, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

void print_usage(const char *prog) {
    printf("FVC384 Hash Utility\n");
    printf("===================\n\n");
    printf("Usage:\n");
    printf("  %s test              - Run built-in tests\n", prog);
    printf("  %s <file>            - Hash a file\n", prog);
    printf("  %s benchmark <file>  - Benchmark file hashing\n", prog);
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "test") == 0) {
        const char *test_strings[] = {
            "",
            "abc",
            "abd",
            "ab",
            "The quick brown fox jumps over the lazy dog",
            "FVC384 - File Verification Content using Tesla's 3-6-9 pattern"
        };
        
        printf("FVC384 Hash Function Test\n");
        printf("==========================\n\n");
        
        for (int i = 0; i < 6; i++) {
            uint8_t digest[48];
            FVC384_hash((const uint8_t*)test_strings[i], strlen(test_strings[i]), digest);
            
            printf("Input: \"%s\"\n", test_strings[i]);
            printf("FVC384: ");
            for (int j = 0; j < 48; j++) {
                printf("%02x", digest[j]);
            }
            printf("\n\n");
        }
        return 0;
    }
    
    if (argc >= 3 && strcmp(argv[1], "benchmark") == 0) {
        const char *filename = argv[2];
        long file_size = get_file_size(filename);
        
        if (file_size < 0) {
            printf("Error: Cannot access file '%s'\n", filename);
            return 1;
        }
        
        char size_str[32];
        format_size(file_size, size_str);
        
        printf("FVC384 Benchmark\n");
        printf("================\n");
        printf("File: %s\n", filename);
        printf("Size: %s\n", size_str);
        if (detect_avx2()) {
            printf("SIMD: AVX2 enabled\n\n");
        } else {
            printf("SIMD: Scalar (no SIMD)\n\n");
        }
        
        uint8_t digest[48];
        FVC384_hash_file(filename, digest);
        
        int num_runs = 5;
        double total_time = 0;
        
        printf("Running %d iterations...\n", num_runs);
        
        for (int i = 0; i < num_runs; i++) {
            clock_t start = clock();
            FVC384_hash_file(filename, digest);
            clock_t end = clock();
            
            double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
            total_time += elapsed;
            printf("  Run %d: %.4f seconds\n", i + 1, elapsed);
        }
        
        double avg_time = total_time / num_runs;
        double throughput = (file_size / (1024.0 * 1024.0)) / avg_time;
        
        printf("\nResults:\n");
        printf("  Average time: %.4f seconds\n", avg_time);
        printf("  Throughput: %.2f MB/s\n", throughput);
        printf("\nFVC384 Hash: ");
        for (int j = 0; j < 48; j++) {
            printf("%02x", digest[j]);
        }
        printf("\n\n");
        
        printf("To compare with SHA-256, run:\n");
        printf("  time sha256sum %s\n", filename);
        
        return 0;
    }
    
    const char *filename = argv[1];
    uint8_t digest[48];
    
    if (FVC384_hash_file(filename, digest) != 0) {
        printf("Error: Cannot read file '%s'\n", filename);
        return 1;
    }
    
    for (int i = 0; i < 48; i++) {
        printf("%02x", digest[i]);
    }
    printf("  %s\n", filename);
    
    return 0;
}