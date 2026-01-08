#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

// For demo: GID is an ASCII string (length-prefixed u16)
// nonce_C and nonce_S are 128-bit (16 bytes)

#define NONCE_LEN 16
#define KPD_LEN   16
#define MAC_LEN   16
#define SEED_LEN  32  /* SHA-256 output */

// Replay window in ms (5 minutes)
#define TS_SKEW_MS (5ULL * 60ULL * 1000ULL)

#endif /* PROTOCOL_H */
