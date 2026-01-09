// kqp_keygen.c
// Derive 128-bit KQP from (seed, QPN_S, QPN_C, timestamp'_ms_low16)
// Requires: tinymt32.h/tinymt32.c and xsadd.h/xsadd.c in your project.
//
// Build example (adjust to your files):
//   gcc -O2 -Wall -Wextra kqp_keygen.c tinymt32.c xsadd.c -o kqp_keygen
//
// Usage (demo main enabled):
//   ./kqp_keygen
//
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tinymt32.h"
#include "xsadd.h"

#ifndef KQP_KEY_BYTES
#define KQP_KEY_BYTES 16
#endif

// ----------------- helpers -----------------
static inline uint32_t rotl32(uint32_t x, uint32_t r) {
    r &= 31u;
    return (x << r) | (x >> ((32u - r) & 31u));
}

static inline uint16_t u64_low16(uint64_t x) {
    return (uint16_t)(x & 0xFFFFu);
}

static void seed32_to_u32_words(const uint8_t seed[32], uint32_t out_words[8]) {
    // big-endian load to be stable across platforms
    for (int i = 0; i < 8; i++) {
        out_words[i] =
            ((uint32_t)seed[i*4 + 0] << 24) |
            ((uint32_t)seed[i*4 + 1] << 16) |
            ((uint32_t)seed[i*4 + 2] <<  8) |
            ((uint32_t)seed[i*4 + 3] <<  0);
    }
}

static inline uint8_t nibble_u16(uint16_t v, int idx /*0..3*/) {
    // idx=0 -> highest nibble, idx=3 -> lowest nibble
    int shift = (3 - idx) * 4;
    return (uint8_t)((v >> shift) & 0x0Fu);
}

// ----------------- core mixing (Algorithm 1 word-level) -----------------
// NOTE: This matches the style we used earlier: rotate/add based mixing with two rotation params.
// If your paper's Algorithm 1 uses a slightly different expression, adjust ONLY this function.
static inline uint32_t alg1_mix_word(uint32_t x, uint32_t y, uint32_t r1, uint32_t r2) {
    // r1,r2 in [1..16] recommended
    // A reasonable lightweight mix:
    //   t = x + rotl(y, r1)
    //   z = rotl(t, r2) ^ y
    // This gives good diffusion while staying close to "rotate/add/xor" style.
    uint32_t t = x + rotl32(y, r1);
    uint32_t z = rotl32(t, r2) ^ y;
    return z;
}

// ----------------- RNG extraction -----------------
static void derive_x_y_from_seed(const uint8_t seed[32], uint32_t x[4], uint32_t y[4]) {
    uint32_t w[8];
    seed32_to_u32_words(seed, w);

    // ---- TinyMT32 -> x[0..3] ----
    tinymt32_t tm;
#if defined(TINYMT32_INIT_BY_ARRAY) || defined(tinymt32_init_by_array)
    // Some distributions provide tinymt32_init_by_array(&tm, init_key, key_length)
    tinymt32_init_by_array(&tm, w, 8);
#else
    // Fallback: fold to single seed
    uint32_t s = w[0] ^ w[1] ^ w[2] ^ w[3] ^ w[4] ^ w[5] ^ w[6] ^ w[7];
    tinymt32_init(&tm, s);
#endif
    for (int i = 0; i < 4; i++) {
        x[i] = tinymt32_generate_uint32(&tm);
    }

    // ---- XSadd -> y[0..3] ----
    xsadd_t xs;
#if defined(XSADD_INIT_BY_ARRAY) || defined(xsadd_init_by_array)
    xsadd_init_by_array(&xs, w, 8);
#else
    // Fallback: use a different fold so x/y streams differ
    uint32_t s2 = (w[7] + 0x9E3779B9u) ^ rotl32(w[3], 7) ^ rotl32(w[5], 13);
    xsadd_init(&xs, s2);
#endif
    for (int i = 0; i < 4; i++) {
        // Common XSadd API names vary; adjust if your header differs.
        y[i] = xsadd_uint32(&xs);
    }
}

// ----------------- public API -----------------
int kqp_derive_key_from_seed_qpn(
    const uint8_t seed[32],
    uint16_t qpn_s,
    uint16_t qpn_c,
    uint64_t timestamp_prime_ms,
    uint8_t out_key[KQP_KEY_BYTES]
) {
    if (!seed || !out_key) return -1;

    // 1) derive x1..x4 and y1..y4 from seed (first PRNG outputs)
    uint32_t x[4], y[4];
    derive_x_y_from_seed(seed, x, y);

    // 2) build r1_0..r1_3 from QPN_S, r2_0..r2_3 from QPN_C, each mixed with ts'_low16
    uint16_t ts16 = u64_low16(timestamp_prime_ms);

    uint16_t qs = (uint16_t)(qpn_s ^ ts16);
    uint16_t qc = (uint16_t)(qpn_c ^ ts16);

    uint32_t r1[4], r2[4];
    for (int i = 0; i < 4; i++) {
        // map nibble 0..15 -> rotation 1..16 to avoid 0-rotation
        r1[i] = (uint32_t)(nibble_u16(qs, i) + 1u);
        r2[i] = (uint32_t)(nibble_u16(qc, i) + 1u);
    }

    // 3) Algorithm 1 word-level generation: 4 words -> 128-bit key
    uint32_t k[4];
    for (int i = 0; i < 4; i++) {
        k[i] = alg1_mix_word(x[i], y[i], r1[i], r2[i]);
    }

    // 4) output as big-endian 16 bytes (portable)
    for (int i = 0; i < 4; i++) {
        out_key[i*4 + 0] = (uint8_t)((k[i] >> 24) & 0xFF);
        out_key[i*4 + 1] = (uint8_t)((k[i] >> 16) & 0xFF);
        out_key[i*4 + 2] = (uint8_t)((k[i] >>  8) & 0xFF);
        out_key[i*4 + 3] = (uint8_t)((k[i] >>  0) & 0xFF);
    }

    return 0;
}

// ----------------- demo main -----------------
#ifdef KQP_KEYGEN_DEMO_MAIN
static void hexprint(const char *tag, const uint8_t *b, size_t n) {
    printf("%s: ", tag);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void) {
    // example inputs (replace with your real seed and QPNs)
    uint8_t seed[32] = {
        0xda,0xe5,0x18,0x10,0x59,0x3a,0x4f,0xd7,
        0x72,0x79,0x14,0x4b,0x93,0xb8,0x98,0x69,
        0xb6,0x22,0xe3,0x06,0x7b,0xdf,0x60,0x6d,
        0x2c,0x69,0x44,0x01,0x1a,0xd1,0x31,0x1f
    };
    uint16_t qpn_s = 0x1234;
    uint16_t qpn_c = 0xBEEF;
    uint64_t ts_prime_ms = 0x0000019B9C699158ull; // example

    uint8_t key[16];
    if (kqp_derive_key_from_seed_qpn(seed, qpn_s, qpn_c, ts_prime_ms, key) != 0) {
        fprintf(stderr, "derive failed\n");
        return 1;
    }
    hexprint("KQP", key, 16);
    return 0;
}
#endif
