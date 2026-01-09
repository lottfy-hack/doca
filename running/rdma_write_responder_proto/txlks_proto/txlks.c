#include "txlks.h"

#include <string.h>
#include <arpa/inet.h>

#include <openssl/sha.h>

#include "tinymt32.h"
#include "xsadd.h"

// Rotate-left 32-bit
static inline uint32_t rotl32(uint32_t x, unsigned r) {
    r &= 31u;
    return (x << r) | (x >> ((32u - r) & 31u));
}

/**
 * TXLKS parameters (paper Section VII-A): r1=3, r2=5, w=32.
 */
enum { TXLKS_R1 = 3, TXLKS_R2 = 5 };

void txlks_derive_key128(const uint8_t *seed_material, size_t seed_material_len,
                         uint8_t out_key16[16]) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(seed_material, seed_material_len, digest);

    // Split digest into two 128-bit seeds.
    const uint8_t *seed1 = digest;
    const uint8_t *seed2 = digest + 16;

    // TinyMT32 and XSadd init functions expect uint32_t arrays.
    uint32_t seed1_words[4];
    uint32_t seed2_words[4];
    for (int i = 0; i < 4; i++) {
        uint32_t w;
        memcpy(&w, seed1 + 4 * i, 4);
        seed1_words[i] = ntohl(w);
        memcpy(&w, seed2 + 4 * i, 4);
        seed2_words[i] = ntohl(w);
    }

    tinymt32_t tm;
    xsadd_t xs;

    // Parameters for TinyMT32 (mat1/mat2/tmat). If you have specific
    // parameters from Table I, set them here. Defaults are common TinyMT32
    // params used in reference code.
    tm.mat1 = 0x8f7011eeU;
    tm.mat2 = 0xfc78ff1fU;
    tm.tmat = 0x3793fdffU;
    tinymt32_init_by_array(&tm, seed1_words, 4);

    xsadd_init_by_array(&xs, seed2_words, 4);

    uint32_t key_words[4];
    for (int j = 0; j < 4; j++) {
        uint32_t xi = tinymt32_generate_uint32(&tm);
        uint32_t yi = xsadd_uint32(&xs);
        uint32_t x_rot = rotl32(xi, TXLKS_R1);
        uint32_t y_rot = rotl32(yi, TXLKS_R2);
        key_words[j] = x_rot + y_rot; // mod 2^32 automatically
    }

    // Output as big-endian bytes.
    for (int i = 0; i < 4; i++) {
        uint32_t be = htonl(key_words[i]);
        memcpy(out_key16 + 4 * i, &be, 4);
    }
}
