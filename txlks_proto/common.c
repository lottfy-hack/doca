#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/md5.h>

int read_n(int fd, void *buf, size_t n) {
    uint8_t *p = (uint8_t*)buf;
    size_t left = n;
    while (left > 0) {
        ssize_t r = read(fd, p, left);
        if (r == 0) return -1; // EOF
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)r;
        left -= (size_t)r;
    }
    return 0;
}

int write_n(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t*)buf;
    size_t left = n;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return -1;
        }
        p += (size_t)w;
        left -= (size_t)w;
    }
    return 0;
}

int write_u16(int fd, uint16_t v) {
    uint16_t be = htons(v);
    return write_n(fd, &be, sizeof(be));
}
int write_u32(int fd, uint32_t v) {
    uint32_t be = htonl(v);
    return write_n(fd, &be, sizeof(be));
}
int write_u64(int fd, uint64_t v) {
    uint64_t be = htobe64(v);
    return write_n(fd, &be, sizeof(be));
}
int read_u16(int fd, uint16_t *v) {
    uint16_t be;
    if (read_n(fd, &be, sizeof(be)) != 0) return -1;
    *v = ntohs(be);
    return 0;
}
int read_u32(int fd, uint32_t *v) {
    uint32_t be;
    if (read_n(fd, &be, sizeof(be)) != 0) return -1;
    *v = ntohl(be);
    return 0;
}
int read_u64(int fd, uint64_t *v) {
    uint64_t be;
    if (read_n(fd, &be, sizeof(be)) != 0) return -1;
    *v = be64toh(be);
    return 0;
}

int write_bytes_u16(int fd, const uint8_t *b, uint16_t len) {
    if (write_u16(fd, len) != 0) return -1;
    if (len == 0) return 0;
    return write_n(fd, b, len);
}

int read_bytes_u16(int fd, uint8_t **out, uint16_t *out_len) {
    uint16_t len;
    if (read_u16(fd, &len) != 0) return -1;
    uint8_t *buf = NULL;
    if (len > 0) {
        buf = (uint8_t*)malloc(len);
        if (!buf) return -1;
        if (read_n(fd, buf, len) != 0) {
            free(buf);
            return -1;
        }
    }
    *out = buf;
    *out_len = len;
    return 0;
}

int write_bytes_u32(int fd, const uint8_t *b, uint32_t len) {
    if (write_u32(fd, len) != 0) return -1;
    if (len == 0) return 0;
    return write_n(fd, b, len);
}

int read_bytes_u32(int fd, uint8_t **out, uint32_t *out_len) {
    uint32_t len;
    if (read_u32(fd, &len) != 0) return -1;
    uint8_t *buf = NULL;
    if (len > 0) {
        buf = (uint8_t*)malloc(len);
        if (!buf) return -1;
        if (read_n(fd, buf, len) != 0) {
            free(buf);
            return -1;
        }
    }
    *out = buf;
    *out_len = len;
    return 0;
}

uint64_t now_unix_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ull + (uint64_t)tv.tv_usec / 1000ull;
}

int sha256_bytes(const uint8_t *in, size_t in_len, uint8_t out32[32]) {
    if (!in && in_len != 0) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int ok = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    if (in_len > 0 && EVP_DigestUpdate(ctx, in, in_len) != 1) goto done;
    unsigned int out_len = 0;
    if (EVP_DigestFinal_ex(ctx, out32, &out_len) != 1) goto done;
    ok = (out_len == 32);

done:
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

int derive_common_seed(const uint8_t kpd[16],
                       const uint8_t nonce_s[16],
                       const uint8_t nonce_c[16],
                       uint64_t timestamp_prime_ms,
                       uint8_t out_seed32[32]) {
    /* Build: K_PD || nonce_S || nonce_C || ts' (u64 big-endian) */
    uint8_t buf[16 + 16 + 16 + 8];
    size_t off = 0;
    memcpy(buf + off, kpd, 16); off += 16;
    memcpy(buf + off, nonce_s, 16); off += 16;
    memcpy(buf + off, nonce_c, 16); off += 16;
    /* big-endian u64 */
    for (int i = 7; i >= 0; i--) {
        buf[off + (7 - i)] = (uint8_t)((timestamp_prime_ms >> (i * 8)) & 0xFF);
    }
    off += 8;
    return sha256_bytes(buf, off, out_seed32);
}

static void openssl_die(const char *where) {
    fprintf(stderr, "OpenSSL error at %s:\n", where);
    ERR_print_errors_fp(stderr);
}

EVP_PKEY *load_privkey_pem(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    EVP_PKEY *p = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return p;
}

X509 *load_x509_pem(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    X509 *c = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return c;
}

int x509_to_pem_bytes(X509 *cert, uint8_t **out, uint32_t *out_len) {
    if (!cert || !out || !out_len) return -1;
    BIO *mem = BIO_new(BIO_s_mem());
    if (!mem) return -1;
    int rc = -1;
    if (PEM_write_bio_X509(mem, cert) != 1) goto done;
    char *data = NULL;
    long len = BIO_get_mem_data(mem, &data);
    if (len <= 0 || len > INT32_MAX) goto done;
    uint8_t *buf = (uint8_t*)malloc((size_t)len);
    if (!buf) goto done;
    memcpy(buf, data, (size_t)len);
    *out = buf;
    *out_len = (uint32_t)len;
    rc = 0;

done:
    BIO_free(mem);
    return rc;
}

EVP_PKEY *pubkey_from_x509(X509 *cert) {
    if (!cert) return NULL;
    return X509_get_pubkey(cert); // returns new ref
}

static void print_cert_modulus_md5(const char *tag, X509 *crt)
{
    EVP_PKEY *pk = X509_get_pubkey(crt);
    if (!pk) { printf("%s: no pubkey\n", tag); return; }

    RSA *rsa = EVP_PKEY_get1_RSA(pk);
    EVP_PKEY_free(pk);
    if (!rsa) { printf("%s: not RSA\n", tag); return; }

    const BIGNUM *n = NULL;
    RSA_get0_key(rsa, &n, NULL, NULL);
    if (!n) { RSA_free(rsa); printf("%s: no modulus\n", tag); return; }

    int nlen = BN_num_bytes(n);
    unsigned char *nbuf = (unsigned char*)OPENSSL_malloc(nlen);
    BN_bn2bin(n, nbuf);

    unsigned char md[MD5_DIGEST_LENGTH];
    MD5(nbuf, nlen, md);
    OPENSSL_free(nbuf);
    RSA_free(rsa);

    printf("%s modulus md5: ", tag);
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", md[i]);
    printf("\n");
}

int sign_sha256(EVP_PKEY *priv, const uint8_t *msg, size_t msg_len,
                uint8_t **sig, size_t *sig_len)
{
    int ret = -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv) != 1) goto done;

    // 强制 RSA PKCS1 v1.5
    EVP_PKEY_CTX *pctx = EVP_MD_CTX_get_pkey_ctx(ctx);
    if (pctx && EVP_PKEY_base_id(priv) == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) goto done;
    }

    if (EVP_DigestSignUpdate(ctx, msg, msg_len) != 1) goto done;

    size_t len = 0;
    if (EVP_DigestSignFinal(ctx, NULL, &len) != 1) goto done;
    uint8_t *out = (uint8_t*)malloc(len);
    if (!out) goto done;

    if (EVP_DigestSignFinal(ctx, out, &len) != 1) { free(out); goto done; }

    *sig = out;
    *sig_len = len;
    ret = 0;

done:
    EVP_MD_CTX_free(ctx);
    return ret;
}


int verify_sha256(EVP_PKEY *pub, const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len)
{
    int ok = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub) != 1) goto done;

    // 强制 RSA PKCS1 v1.5
    EVP_PKEY_CTX *pctx = EVP_MD_CTX_get_pkey_ctx(ctx);
    if (pctx && EVP_PKEY_base_id(pub) == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) goto done;
    }

    if (EVP_DigestVerifyUpdate(ctx, msg, msg_len) != 1) goto done;

    ok = (EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1) ? 1 : 0;

done:
    EVP_MD_CTX_free(ctx);
    return ok;
}


int rsa_oaep_encrypt(EVP_PKEY *pub, const uint8_t *pt, size_t pt_len,
                     uint8_t **ct, size_t *ct_len) {
    if (!pub || !pt || !ct || !ct_len) return -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub, NULL);
    if (!ctx) return -1;
    int rc = -1;
    if (EVP_PKEY_encrypt_init(ctx) != 1) goto done;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) goto done;

    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, pt, pt_len) != 1) goto done;
    uint8_t *out = (uint8_t*)malloc(outlen);
    if (!out) goto done;
    if (EVP_PKEY_encrypt(ctx, out, &outlen, pt, pt_len) != 1) {
        free(out);
        goto done;
    }
    *ct = out;
    *ct_len = outlen;
    rc = 0;

done:
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

int rsa_oaep_decrypt(EVP_PKEY *priv, const uint8_t *ct, size_t ct_len,
                     uint8_t **pt, size_t *pt_len) {
    if (!priv || !ct || !pt || !pt_len) return -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) return -1;
    int rc = -1;
    if (EVP_PKEY_decrypt_init(ctx) != 1) goto done;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) goto done;

    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ct, ct_len) != 1) goto done;
    uint8_t *out = (uint8_t*)malloc(outlen);
    if (!out) goto done;
    if (EVP_PKEY_decrypt(ctx, out, &outlen, ct, ct_len) != 1) {
        free(out);
        goto done;
    }
    *pt = out;
    *pt_len = outlen;
    rc = 0;

done:
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

int hmac_sha256_trunc16(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out16[16]) {
    unsigned int len = 0;
    uint8_t mac[32];
    if (!HMAC(EVP_sha256(), key, (int)key_len, msg, msg_len, mac, &len)) return -1;
    if (len < 16) return -1;
    memcpy(out16, mac, 16);
    return 0;
}
