// client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#if defined(__linux__)
#include <endian.h>   // htobe64
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64((x))
#endif

#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>

#include "common.h"
#include "protocol.h"
#include "txlks.h"

static void hex_print(const char *label, const uint8_t *buf, size_t len)
{
    size_t i;
    printf("%s (%zu bytes):\n", label, len);
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else printf(" ");
    }
    if (len % 16 != 0) printf("\n");
}

static int connect_tcp(const char *host, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        perror("inet_pton");
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    // avoid hanging forever
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return fd;
}

/*
msg1:  GID_C || Cert_C || Sign_{PrivC}(GID_C || timestamp) || timestamp

wire format:
  u16 gid_len | gid bytes
  u32 cert_len | cert_pem bytes
  u16 sig_len  | sig bytes
  u64 timestamp_ms
*/
static int send_msg1(int fd,
                     const uint8_t *gid_c_bytes, uint16_t gid_c_len,
                     X509 *cert_c,
                     EVP_PKEY *priv_c,
                     uint64_t *out_timestamp_ms)
{
    int rc = -1;
    uint8_t *cert_bytes = NULL;
    uint32_t cert_len = 0;
    uint8_t *sig = NULL;
    size_t sig_len = 0;

    uint64_t ts = now_unix_ms();
    *out_timestamp_ms = ts;

    if (x509_to_pem_bytes(cert_c, &cert_bytes, &cert_len) != 0) {
        fprintf(stderr, "x509_to_pem_bytes failed\n");
        goto out;
    }

    // Build signing input: gid_bytes || htobe64(timestamp_ms)
    uint8_t to_sign[2048];
    if ((size_t)gid_c_len + 8 > sizeof(to_sign)) {
        fprintf(stderr, "GID too long\n");
        goto out;
    }

    size_t off = 0;
    memcpy(to_sign + off, gid_c_bytes, gid_c_len);
    off += gid_c_len;

    uint64_t ts_be = htobe64(ts);
    memcpy(to_sign + off, &ts_be, 8);
    off += 8;

    // hex_print("[client] msg1 to_sign", to_sign, off);

    if (sign_sha256(priv_c, to_sign, off, &sig, &sig_len) != 0) {
        fprintf(stderr, "sign_sha256 failed\n");
        goto out;
    }

    if (sig_len > 65535) {
        fprintf(stderr, "signature too long\n");
        goto out;
    }

    // Send msg1 fields
    if (write_u16(fd, gid_c_len) != 0) goto out;
    if (write_n(fd, gid_c_bytes, gid_c_len) != 0) goto out;

    if (write_u32(fd, cert_len) != 0) goto out;
    if (write_n(fd, cert_bytes, cert_len) != 0) goto out;

    if (write_u16(fd, (uint16_t)sig_len) != 0) goto out;
    if (write_n(fd, sig, sig_len) != 0) goto out;

    if (write_u64(fd, ts) != 0) goto out;

    rc = 0;

out:
    if (cert_bytes) free(cert_bytes);
    if (sig) free(sig);
    return rc;
}

/*
msg2:  GID_S || Cert_S || ENC_{PubC}(K_PD) || Sign_{PrivS}( ENC || timestamp') || timestamp'

wire format:
  u16 gid_len | gid bytes
  u32 cert_len | cert_pem bytes
  u32 enc_len  | enc bytes
  u16 sig_len  | sig bytes
  u64 timestamp'_ms
*/
static int recv_msg2(int fd,
                     uint8_t **out_gid_s_bytes, uint16_t *out_gid_s_len,
                     X509 **out_cert_s,
                     uint8_t **out_enc_kpd, uint32_t *out_enc_kpd_len,
                     uint8_t **out_sig_s, uint16_t *out_sig_s_len,
                     uint64_t *out_ts_prime)
{
    int rc = -1;

    uint16_t gid_len = 0;
    uint8_t *gid_bytes = NULL;

    uint32_t cert_len = 0;
    uint8_t *cert_bytes = NULL;
    X509 *cert_s = NULL;

    uint32_t enc_len = 0;
    uint8_t *enc = NULL;

    uint16_t sig_len = 0;
    uint8_t *sig = NULL;

    uint64_t ts_prime = 0;

    if (read_u16(fd, &gid_len) != 0) goto out;
    gid_bytes = (uint8_t*)malloc(gid_len);
    if (!gid_bytes) goto out;
    if (read_n(fd, gid_bytes, gid_len) != 0) goto out;

    if (read_u32(fd, &cert_len) != 0) goto out;
    cert_bytes = (uint8_t*)malloc(cert_len);
    if (!cert_bytes) goto out;
    if (read_n(fd, cert_bytes, cert_len) != 0) goto out;

    BIO *bio = BIO_new_mem_buf(cert_bytes, (int)cert_len);
    if (!bio) goto out;
    cert_s = PEM_read_bio_X509(bio, NULL, 0, NULL);
    BIO_free(bio);
    bio = NULL;

    if (!cert_s) {
        fprintf(stderr, "Failed to parse server cert\n");
        goto out;
    }

    if (read_u32(fd, &enc_len) != 0) goto out;
    enc = (uint8_t*)malloc(enc_len);
    if (!enc) goto out;
    if (read_n(fd, enc, enc_len) != 0) goto out;

    if (read_u16(fd, &sig_len) != 0) goto out;
    sig = (uint8_t*)malloc(sig_len);
    if (!sig) goto out;
    if (read_n(fd, sig, sig_len) != 0) goto out;

    if (read_u64(fd, &ts_prime) != 0) goto out;

    *out_gid_s_bytes = gid_bytes; gid_bytes = NULL;
    *out_gid_s_len = gid_len;
    *out_cert_s = cert_s; cert_s = NULL;
    *out_enc_kpd = enc; enc = NULL;
    *out_enc_kpd_len = enc_len;
    *out_sig_s = sig; sig = NULL;
    *out_sig_s_len = sig_len;
    *out_ts_prime = ts_prime;

    rc = 0;

out:
    if (gid_bytes) free(gid_bytes);
    if (cert_bytes) free(cert_bytes);
    if (cert_s) X509_free(cert_s);
    if (enc) free(enc);
    if (sig) free(sig);
    return rc;
}

static int client_handshake(int fd,
                            const char *gid_c_str,
                            const char *cert_c_path,
                            const char *priv_c_path,
                            const char *server_gid_expected_str)
{
    int rc = -1;

    X509 *cert_c = NULL;
    EVP_PKEY *priv_c = NULL;

    uint8_t *gid_s_bytes = NULL;
    uint16_t gid_s_len = 0;
    X509 *cert_s = NULL;
    uint8_t *enc_kpd = NULL;
    uint32_t enc_kpd_len = 0;
    uint8_t *sig_s = NULL;
    uint16_t sig_s_len = 0;
    uint64_t ts_prime = 0;

    uint8_t *kpd = NULL;
    size_t kpd_len = 0;

    // client GID bytes/len (use explicit len, not strlen later)
    const uint8_t *gid_c_bytes = (const uint8_t*)gid_c_str;
    uint16_t gid_c_len = (uint16_t)strlen(gid_c_str);

    cert_c = load_x509_pem(cert_c_path);
    priv_c = load_privkey_pem(priv_c_path);
    if (!cert_c || !priv_c) {
        fprintf(stderr, "Failed to load client cert/key\n");
        goto out;
    }

    uint64_t ts1 = 0;
    if (send_msg1(fd, gid_c_bytes, gid_c_len, cert_c, priv_c, &ts1) != 0) {
        fprintf(stderr, "send_msg1 failed\n");
        goto out;
    }

    if (recv_msg2(fd, &gid_s_bytes, &gid_s_len, &cert_s,
                  &enc_kpd, &enc_kpd_len, &sig_s, &sig_s_len, &ts_prime) != 0) {
        fprintf(stderr, "recv_msg2 failed\n");
        goto out;
    }

    // If user provided expected server GID (string), check it against received bytes
    if (server_gid_expected_str) {
        size_t exp_len = strlen(server_gid_expected_str);
        if (exp_len != gid_s_len || memcmp(gid_s_bytes, server_gid_expected_str, gid_s_len) != 0) {
            fprintf(stderr, "Unexpected server GID\n");
            goto out;
        }
    }

    // Verify server signature over (ENC || htobe64(ts_prime))
    EVP_PKEY *pub_s = pubkey_from_x509(cert_s);
    if (!pub_s) {
        fprintf(stderr, "pubkey_from_x509 failed\n");
        goto out;
    }

    uint64_t tsp_be = htobe64(ts_prime);

    size_t vlen = (size_t)enc_kpd_len + 8;
    uint8_t *to_verify = (uint8_t*)malloc(vlen);
    if (!to_verify) {
        EVP_PKEY_free(pub_s);
        goto out;
    }
    memcpy(to_verify, enc_kpd, enc_kpd_len);
    memcpy(to_verify + enc_kpd_len, &tsp_be, 8);

    // hex_print("[client] msg2 to_verify", to_verify, vlen);

    // IMPORTANT: verify_sha256 returns 1 on success, 0 on failure.
    if (verify_sha256(pub_s, to_verify, vlen, sig_s, sig_s_len) != 1) {
        fprintf(stderr, "Server signature verification failed\n");
        free(to_verify);
        EVP_PKEY_free(pub_s);
        goto out;
    }
    free(to_verify);
    EVP_PKEY_free(pub_s);

    // Timestamp freshness check
    uint64_t now = now_unix_ms();
    if (ts_prime > now + TS_SKEW_MS || now > ts_prime + TS_SKEW_MS) {
        fprintf(stderr, "Stale ts_prime\n");
        goto out;
    }

    // Decrypt K_PD
    if (rsa_oaep_decrypt(priv_c, enc_kpd, enc_kpd_len, &kpd, &kpd_len) != 0) {
        fprintf(stderr, "rsa_oaep_decrypt failed\n");
        goto out;
    }
    if (kpd_len != KPD_LEN) {
        fprintf(stderr, "Unexpected K_PD len %zu (expected %d)\n", kpd_len, KPD_LEN);
        goto out;
    }

    // ---------- msg3 ----------
    uint8_t nonce_c[NONCE_LEN];
    if (RAND_bytes(nonce_c, sizeof(nonce_c)) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        goto out;
    }

    // seed_C = h(K_PD || nonce_C || timestamp')  -> for tk_C
    uint8_t seed_input_c[KPD_LEN + NONCE_LEN + 8];
    memcpy(seed_input_c, kpd, KPD_LEN);
    memcpy(seed_input_c + KPD_LEN, nonce_c, NONCE_LEN);
    memcpy(seed_input_c + KPD_LEN + NONCE_LEN, &tsp_be, 8);

    uint8_t seed_c[32];
    sha256_bytes(seed_input_c, sizeof(seed_input_c), seed_c);

    uint8_t tk_c[16];
    txlks_derive_key128(seed_c, sizeof(seed_c), tk_c);

    // MAC3 = HMAC_{tk_c}(nonce_C || GID_S || GID_C) trunc16
    size_t mac3_msg_len = (size_t)NONCE_LEN + (size_t)gid_s_len + (size_t)gid_c_len;
    uint8_t *mac3_msg = (uint8_t*)malloc(mac3_msg_len);
    if (!mac3_msg) goto out;

    size_t off = 0;
    memcpy(mac3_msg + off, nonce_c, NONCE_LEN); off += NONCE_LEN;
    memcpy(mac3_msg + off, gid_s_bytes, gid_s_len); off += gid_s_len;
    memcpy(mac3_msg + off, gid_c_bytes, gid_c_len); off += gid_c_len;

    uint8_t mac3[MAC_LEN];
    if (hmac_sha256_trunc16(tk_c, sizeof(tk_c), mac3_msg, mac3_msg_len, mac3) != 0) {
        fprintf(stderr, "hmac mac3 failed\n");
        free(mac3_msg);
        goto out;
    }
    free(mac3_msg);

    if (write_n(fd, nonce_c, NONCE_LEN) != 0) goto out;
    if (write_n(fd, mac3, MAC_LEN) != 0) goto out;

    // ---------- msg4 ----------
    uint8_t nonce_s[NONCE_LEN];
    uint8_t mac4[MAC_LEN];

    if (read_n(fd, nonce_s, NONCE_LEN) != 0) goto out;
    if (read_n(fd, mac4, MAC_LEN) != 0) goto out;

    // seed_S = h(K_PD || nonce_S || timestamp') -> for tk_S
    uint8_t seed_input_s[KPD_LEN + NONCE_LEN + 8];
    memcpy(seed_input_s, kpd, KPD_LEN);
    memcpy(seed_input_s + KPD_LEN, nonce_s, NONCE_LEN);
    memcpy(seed_input_s + KPD_LEN + NONCE_LEN, &tsp_be, 8);

    uint8_t seed_s[32];
    sha256_bytes(seed_input_s, sizeof(seed_input_s), seed_s);

    uint8_t tk_s[16];
    txlks_derive_key128(seed_s, sizeof(seed_s), tk_s);

    // Verify MAC4 = HMAC_{tk_s}(nonce_C || nonce_S || GID_S || GID_C) trunc16
    size_t mac4_msg_len = (size_t)NONCE_LEN + (size_t)NONCE_LEN + (size_t)gid_s_len + (size_t)gid_c_len;
    uint8_t *mac4_msg = (uint8_t*)malloc(mac4_msg_len);
    if (!mac4_msg) goto out;

    off = 0;
    memcpy(mac4_msg + off, nonce_c, NONCE_LEN); off += NONCE_LEN;
    memcpy(mac4_msg + off, nonce_s, NONCE_LEN); off += NONCE_LEN;
    memcpy(mac4_msg + off, gid_s_bytes, gid_s_len); off += gid_s_len;
    memcpy(mac4_msg + off, gid_c_bytes, gid_c_len); off += gid_c_len;

    uint8_t expected_mac4[MAC_LEN];
    if (hmac_sha256_trunc16(tk_s, sizeof(tk_s), mac4_msg, mac4_msg_len, expected_mac4) != 0) {
        fprintf(stderr, "hmac mac4 failed\n");
        free(mac4_msg);
        goto out;
    }
    free(mac4_msg);

    if (CRYPTO_memcmp(expected_mac4, mac4, MAC_LEN) != 0) {
        fprintf(stderr, "Server MAC verification failed\n");
        goto out;
    }

    printf("Handshake success!\n");

    printf("GID_S=");
    fwrite(gid_s_bytes, 1, gid_s_len, stdout);
    printf("\n");

    printf("Derived tk_C (hex): ");
    for (int i = 0; i < 16; i++) printf("%02x", tk_c[i]);
    printf("\n");

    printf("Derived tk_S (hex): ");
    for (int i = 0; i < 16; i++) printf("%02x", tk_s[i]);
    printf("\n");

    // Shared seed per your final design:
    // seed = h(K_PD || nonce_S || nonce_C || timestamp')
    uint8_t shared_seed[SEED_LEN];
    if (derive_common_seed(kpd, nonce_s, nonce_c, ts_prime, shared_seed) != 0) {
        fprintf(stderr, "derive_common_seed failed\n");
        goto out;
    }
    printf("Shared seed (hex): ");
    for (int i = 0; i < SEED_LEN; i++) printf("%02x", shared_seed[i]);
    printf("\n");

    rc = 0;

out:
    if (kpd) free(kpd);

    if (gid_s_bytes) free(gid_s_bytes);
    if (cert_s) X509_free(cert_s);
    if (enc_kpd) free(enc_kpd);
    if (sig_s) free(sig_s);

    if (cert_c) X509_free(cert_c);
    if (priv_c) EVP_PKEY_free(priv_c);

    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 7) {
        fprintf(stderr,
                "Usage: %s <server_ip> <port> <GID_C> <client_cert.pem> <client_key.pem> <expected_GID_S>\n",
                argv[0]);
        return 2;
    }

    const char *host = argv[1];
    uint16_t port = (uint16_t)atoi(argv[2]);
    const char *gid_c = argv[3];
    const char *cert_c = argv[4];
    const char *key_c  = argv[5];
    const char *gid_s_expected = argv[6];

    int fd = connect_tcp(host, port);
    if (fd < 0) return 1;

    int rc = client_handshake(fd, gid_c, cert_c, key_c, gid_s_expected);

    close(fd);
    return (rc == 0) ? 0 : 1;
}
