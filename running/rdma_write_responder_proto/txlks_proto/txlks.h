#ifndef TXLKS_H
#define TXLKS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Derive a 128-bit key using TXLKS (TinyMT32 + XSadd + rotate/add).
 *
 * Inputs:
 *  - seed_material: arbitrary bytes (e.g., SHA-256 output)
 *  - seed_material_len: length of seed_material
 *
 * Output:
 *  - out_key16: 16-byte derived key
 */
void txlks_derive_key128(const uint8_t *seed_material, size_t seed_material_len,
                         uint8_t out_key16[16]);

#ifdef __cplusplus
}
#endif

#endif /* TXLKS_H */
