#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- basic IO helpers (blocking) ----
int read_n(int fd, void *buf, size_t n);
int write_n(int fd, const void *buf, size_t n);

// ---- serialization helpers ----
int write_u16(int fd, uint16_t v);
int write_u32(int fd, uint32_t v);
int write_u64(int fd, uint64_t v);
int read_u16(int fd, uint16_t *v);
int read_u32(int fd, uint32_t *v);
int read_u64(int fd, uint64_t *v);

int write_bytes_u16(int fd, const uint8_t *b, uint16_t len);
int read_bytes_u16(int fd, uint8_t **out, uint16_t *out_len);
int write_bytes_u32(int fd, const uint8_t *b, uint32_t len);
int read_bytes_u32(int fd, uint8_t **out, uint32_t *out_len);

// ---- crypto helpers ----
uint64_t now_unix_ms(void);
int sha256_bytes(const uint8_t *in, size_t in_len, uint8_t out32[32]);

/* seed = SHA256(K_PD || nonce_S || nonce_C || timestamp_prime_u64_be) */
int derive_common_seed(const uint8_t kpd[16],
                       const uint8_t nonce_s[16],
                       const uint8_t nonce_c[16],
                       uint64_t timestamp_prime_ms,
                       uint8_t out_seed32[32]);

// Load X509 cert and private key
EVP_PKEY *load_privkey_pem(const char *path);
X509 *load_x509_pem(const char *path);

// Export cert to PEM bytes
int x509_to_pem_bytes(X509 *cert, uint8_t **out, uint32_t *out_len);

// Verify cert is parseable and extract public key
EVP_PKEY *pubkey_from_x509(X509 *cert);

// Signature: RSA/ECDSA via EVP, using SHA-256
int sign_sha256(EVP_PKEY *priv, const uint8_t *msg, size_t msg_len,
                uint8_t **sig, size_t *sig_len);
int verify_sha256(EVP_PKEY *pub, const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len);

// RSA-OAEP encrypt/decrypt (for K_PD)
int rsa_oaep_encrypt(EVP_PKEY *pub, const uint8_t *pt, size_t pt_len,
                     uint8_t **ct, size_t *ct_len);
int rsa_oaep_decrypt(EVP_PKEY *priv, const uint8_t *ct, size_t ct_len,
                     uint8_t **pt, size_t *pt_len);

// HMAC-SHA256 MAC (we truncate to 16 bytes for compactness)
int hmac_sha256_trunc16(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out16[16]);

// void hex_print(const char *label, const uint8_t *buf, size_t len);


#ifdef __cplusplus
}
#endif

#endif /* COMMON_H */
