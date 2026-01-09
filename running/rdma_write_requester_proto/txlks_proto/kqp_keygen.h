#ifndef KQP_KEYGEN_H
#define KQP_KEYGEN_H

#include <stdint.h>
#define KQP_KEY_BYTES 16

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Derive a 128-bit AES key from a shared seed and session parameters.
 *
 * @param[in]  seed          The shared 32-byte seed derived from handshake.
 * @param[in]  qpn_s         Server (Responder) Queue Pair Number.
 * @param[in]  qpn_c         Client (Requester) Queue Pair Number.
 * @param[in]  timestamp_ms  Timestamp in milliseconds (ts_prime).
 * @param[out] kqp_out       Output buffer for the 128-bit (16-byte) key.
 *
 * @return 0 on success, negative value on error.
 */
int kqp_derive_key_from_seed_qpn(
    const uint8_t *seed,
    uint16_t qpn_s,
    uint16_t qpn_c,
    uint64_t timestamp_ms,
    uint8_t *kqp_out
);

#ifdef __cplusplus
}
#endif

#endif /* KQP_KEYGEN_H */
