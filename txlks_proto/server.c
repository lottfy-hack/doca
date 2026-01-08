#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>

#include "common.h"
#include "protocol.h"
#include "txlks.h"

/* ---------- debug hex print ---------- */
void hex_print(const char *label, const uint8_t *buf, size_t len)
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

/* ---------- helpers ---------- */
static void u64_to_be(uint64_t x, uint8_t out[8])
{
    out[0] = (uint8_t)((x >> 56) & 0xff);
    out[1] = (uint8_t)((x >> 48) & 0xff);
    out[2] = (uint8_t)((x >> 40) & 0xff);
    out[3] = (uint8_t)((x >> 32) & 0xff);
    out[4] = (uint8_t)((x >> 24) & 0xff);
    out[5] = (uint8_t)((x >> 16) & 0xff);
    out[6] = (uint8_t)((x >>  8) & 0xff);
    out[7] = (uint8_t)((x >>  0) & 0xff);
}

static int set_sock_timeout(int fd, int sec)
{
    struct timeval tv;
    tv.tv_sec = sec;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) return -1;
    return 0;
}

static int listen_tcp(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

/*
Msg1:
  u16 gid_len | gid_bytes
  u32 cert_len | cert_pem_bytes
  u16 sig_len | sig_bytes
  u64 timestamp_ms
*/
static int read_msg1(int fd,
                     uint8_t **gid_c_bytes, uint16_t *gid_c_len,
                     X509 **cert_c,
                     uint8_t **sig, uint16_t *sig_len,
                     uint64_t *ts_ms)
{
    *gid_c_bytes = NULL;
    *cert_c = NULL;
    *sig = NULL;

    // GID_C
    if (read_u16(fd, gid_c_len) != 0) return -1;
    if (*gid_c_len == 0) return -1;

    uint8_t *gid_buf = (uint8_t*)malloc(*gid_c_len);
    if (!gid_buf) return -1;
    if (read_n(fd, gid_buf, *gid_c_len) != 0) { free(gid_buf); return -1; }
    *gid_c_bytes = gid_buf;

    // Cert_C (PEM)
    uint32_t cert_len;
    if (read_u32(fd, &cert_len) != 0) return -1;
    if (cert_len == 0 || cert_len > (10u * 1024u * 1024u)) { // 10MB guard
        fprintf(stderr, "[server] cert_len invalid: %u\n", cert_len);
        return -1;
    }

    uint8_t *cert_pem = (uint8_t*)malloc(cert_len);
    if (!cert_pem) return -1;
    if (read_n(fd, cert_pem, cert_len) != 0) { free(cert_pem); return -1; }

    BIO *b = BIO_new_mem_buf(cert_pem, (int)cert_len);
    if (!b) { free(cert_pem); return -1; }
    *cert_c = PEM_read_bio_X509(b, NULL, NULL, NULL);
    BIO_free(b);
    free(cert_pem);

    if (!*cert_c) {
        fprintf(stderr, "[server] failed to parse client cert\n");
        return -1;
    }

    // Signature
    if (read_u16(fd, sig_len) != 0) return -1;
    if (*sig_len == 0) return -1;

    uint8_t *sig_buf = (uint8_t*)malloc(*sig_len);
    if (!sig_buf) return -1;
    if (read_n(fd, sig_buf, *sig_len) != 0) { free(sig_buf); return -1; }
    *sig = sig_buf;

    // Timestamp
    if (read_u64(fd, ts_ms) != 0) return -1;
    return 0;
}

/*
Msg2:
  u16 gid_s_len | gid_s_bytes
  u32 cert_s_len | cert_s_pem
  u32 enc_len | enc_kpd
  u16 sig_len | sig( enc||ts2 )
  u64 ts2_ms
*/
static int send_msg2(int fd,
                     const uint8_t *gid_s_bytes, uint16_t gid_s_len,
                     X509 *cert_s,
                     const uint8_t *enc_kpd, uint32_t enc_kpd_len,
                     EVP_PKEY *priv_s,
                     uint64_t ts2_ms)
{
    // GID_S
    if (write_u16(fd, gid_s_len) != 0) return -1;
    if (write_n(fd, gid_s_bytes, gid_s_len) != 0) return -1;

    // Cert_S
    uint8_t *cert_pem = NULL;
    uint32_t cert_len = 0;
    if (x509_to_pem_bytes(cert_s, &cert_pem, &cert_len) != 0) return -1;
    if (write_u32(fd, cert_len) != 0) { free(cert_pem); return -1; }
    if (write_n(fd, cert_pem, cert_len) != 0) { free(cert_pem); return -1; }
    free(cert_pem);

    // ENC_{PubC}(K_PD)
    if (write_u32(fd, enc_kpd_len) != 0) return -1;
    if (write_n(fd, enc_kpd, enc_kpd_len) != 0) return -1;

    // Sign_{PrivS}( ENC || timestamp' )
    uint8_t tsbuf[8];
    u64_to_be(ts2_ms, tsbuf);

    size_t to_sign_len = (size_t)enc_kpd_len + 8;
    uint8_t *to_sign = (uint8_t*)malloc(to_sign_len);
    if (!to_sign) return -1;

    memcpy(to_sign, enc_kpd, enc_kpd_len);
    memcpy(to_sign + enc_kpd_len, tsbuf, 8);

    uint8_t *sig = NULL;
    size_t sig_len = 0;
    if (sign_sha256(priv_s, to_sign, to_sign_len, &sig, &sig_len) != 0) {
        free(to_sign);
        return -1;
    }
    free(to_sign);

    if (sig_len > 0xffffu) { free(sig); return -1; }
    if (write_u16(fd, (uint16_t)sig_len) != 0) { free(sig); return -1; }
    if (write_n(fd, sig, sig_len) != 0) { free(sig); return -1; }
    free(sig);

    // timestamp'
    if (write_u64(fd, ts2_ms) != 0) return -1;
    return 0;
}

static int server_handle(int cfd,
                         const char *gid_s_str,
                         const char *cert_s_path,
                         const char *key_s_path)
{
    X509 *cert_s = load_x509_pem(cert_s_path);
    EVP_PKEY *priv_s = load_privkey_pem(key_s_path);
    if (!cert_s || !priv_s) {
        fprintf(stderr, "[server] load server cert/key failed\n");
        if (cert_s) X509_free(cert_s);
        if (priv_s) EVP_PKEY_free(priv_s);
        return -1;
    }

    /* prepare GID_S bytes (use exact strlen once) */
    uint16_t gid_s_len = (uint16_t)strlen(gid_s_str);
    const uint8_t *gid_s_bytes = (const uint8_t*)gid_s_str;

    /* ---- Msg1 ---- */
    uint8_t *gid_c_bytes = NULL;
    uint16_t gid_c_len = 0;
    X509 *cert_c = NULL;
    uint8_t *sig1 = NULL;
    uint16_t sig1_len = 0;
    uint64_t ts1_ms = 0;

    if (read_msg1(cfd, &gid_c_bytes, &gid_c_len, &cert_c, &sig1, &sig1_len, &ts1_ms) != 0) {
        fprintf(stderr, "[server] failed reading msg1\n");
        goto fail;
    }

    uint64_t now = now_unix_ms();
    if (ts1_ms + TS_SKEW_MS < now || ts1_ms > now + TS_SKEW_MS) {
        fprintf(stderr, "[server] msg1 timestamp out of window (ts=%llu now=%llu)\n",
                (unsigned long long)ts1_ms, (unsigned long long)now);
        goto fail;
    }

    EVP_PKEY *pub_c = pubkey_from_x509(cert_c);
    if (!pub_c) {
        fprintf(stderr, "[server] cannot extract pubkey from client cert\n");
        goto fail;
    }

    /* Verify Sign_{PrivC}(GID_C || timestamp) with EXACT gid_len bytes */
    uint8_t tsbuf1[8];
    u64_to_be(ts1_ms, tsbuf1);

    size_t m1_len = (size_t)gid_c_len + 8;
    uint8_t *m1 = (uint8_t*)malloc(m1_len);
    if (!m1) { EVP_PKEY_free(pub_c); goto fail; }

    memcpy(m1, gid_c_bytes, gid_c_len);
    memcpy(m1 + gid_c_len, tsbuf1, 8);

    /* debug: print what server actually verifies */
    // hex_print("[server] msg1 to_verify = GID_C||ts1", m1, m1_len);

    if (verify_sha256(pub_c, m1, m1_len, sig1, sig1_len) != 1) {
        fprintf(stderr, "[server] msg1 signature verify failed\n");
        free(m1);
        EVP_PKEY_free(pub_c);
        goto fail;
    }
    free(m1);

    fprintf(stdout, "[server] msg1 signature verified\n");

    /* ---- Msg2 ---- */
    uint8_t kpd[KPD_LEN];
    if (RAND_bytes(kpd, sizeof(kpd)) != 1) {
        fprintf(stderr, "[server] RAND_bytes failed\n");
        EVP_PKEY_free(pub_c);
        goto fail;
    }

    uint8_t *enc_kpd = NULL;
    size_t enc_kpd_len_sz = 0;
    if (rsa_oaep_encrypt(pub_c, kpd, sizeof(kpd), &enc_kpd, &enc_kpd_len_sz) != 0) {
        fprintf(stderr, "[server] RSA OAEP encrypt failed\n");
        EVP_PKEY_free(pub_c);
        goto fail;
    }
    EVP_PKEY_free(pub_c);

    if (enc_kpd_len_sz > 0xffffffffu) {
        fprintf(stderr, "[server] enc_kpd too large\n");
        free(enc_kpd);
        goto fail;
    }
    uint32_t enc_kpd_len = (uint32_t)enc_kpd_len_sz;

    uint64_t ts2_ms = now_unix_ms();
    if (send_msg2(cfd, gid_s_bytes, gid_s_len, cert_s, enc_kpd, enc_kpd_len, priv_s, ts2_ms) != 0) {
        fprintf(stderr, "[server] failed sending msg2\n");
        free(enc_kpd);
        goto fail;
    }
    free(enc_kpd);

    /* ---- Msg3: nonce_C || MAC_{tk_C}(nonce_C||GID_S||GID_C) ---- */
    uint8_t nonce_c[NONCE_LEN];
    if (read_n(cfd, nonce_c, sizeof(nonce_c)) != 0) {
        fprintf(stderr, "[server] read nonce_c failed\n");
        goto fail;
    }
    uint8_t mac3[MAC_LEN];
    if (read_n(cfd, mac3, sizeof(mac3)) != 0) {
        fprintf(stderr, "[server] read mac3 failed\n");
        goto fail;
    }

    /* seed_C = H(K_PD || nonce_C || timestamp')  (legacy for tk_C verification) */
    uint8_t tsbuf2[8];
    u64_to_be(ts2_ms, tsbuf2);

    uint8_t seed_in[KPD_LEN + NONCE_LEN + 8];
    memcpy(seed_in, kpd, KPD_LEN);
    memcpy(seed_in + KPD_LEN, nonce_c, NONCE_LEN);
    memcpy(seed_in + KPD_LEN + NONCE_LEN, tsbuf2, 8);

    uint8_t seed_c[32];
    sha256_bytes(seed_in, sizeof(seed_in), seed_c);

    uint8_t tk_c[16];
    txlks_derive_key128(seed_c, sizeof(seed_c), tk_c);

    /* MAC3 message = nonce_C || GID_S || GID_C (use gid_c_len exact bytes) */
    size_t m3_len = (size_t)NONCE_LEN + (size_t)gid_s_len + (size_t)gid_c_len;
    uint8_t *m3 = (uint8_t*)malloc(m3_len);
    if (!m3) goto fail;

    memcpy(m3, nonce_c, NONCE_LEN);
    memcpy(m3 + NONCE_LEN, gid_s_bytes, gid_s_len);
    memcpy(m3 + NONCE_LEN + gid_s_len, gid_c_bytes, gid_c_len);

    uint8_t mac3_calc[MAC_LEN];
    if (hmac_sha256_trunc16(tk_c, sizeof(tk_c), m3, m3_len, mac3_calc) != 0) {
        free(m3);
        goto fail;
    }
    free(m3);

    if (CRYPTO_memcmp(mac3, mac3_calc, MAC_LEN) != 0) {
        fprintf(stderr, "[server] MAC3 verify failed\n");
        goto fail;
    }
    fprintf(stdout, "[server] MAC3 verified; client authenticated\n");

    /* ---- Msg4: nonce_S || MAC_{tk_S}(nonce_C||nonce_S||GID_S||GID_C) ---- */
    uint8_t nonce_s[NONCE_LEN];
    if (RAND_bytes(nonce_s, sizeof(nonce_s)) != 1) {
        fprintf(stderr, "[server] RAND_bytes nonce_s failed\n");
        goto fail;
    }

    /* seed_S = H(K_PD || nonce_S || timestamp') (legacy for tk_S) */
    uint8_t seed_in_s[KPD_LEN + NONCE_LEN + 8];
    memcpy(seed_in_s, kpd, KPD_LEN);
    memcpy(seed_in_s + KPD_LEN, nonce_s, NONCE_LEN);
    memcpy(seed_in_s + KPD_LEN + NONCE_LEN, tsbuf2, 8);

    uint8_t seed_s[32];
    sha256_bytes(seed_in_s, sizeof(seed_in_s), seed_s);

    uint8_t tk_s[16];
    txlks_derive_key128(seed_s, sizeof(seed_s), tk_s);

    size_t m4_len = (size_t)NONCE_LEN + (size_t)NONCE_LEN + (size_t)gid_s_len + (size_t)gid_c_len;
    uint8_t *m4 = (uint8_t*)malloc(m4_len);
    if (!m4) goto fail;

    memcpy(m4, nonce_c, NONCE_LEN);
    memcpy(m4 + NONCE_LEN, nonce_s, NONCE_LEN);
    memcpy(m4 + 2*NONCE_LEN, gid_s_bytes, gid_s_len);
    memcpy(m4 + 2*NONCE_LEN + gid_s_len, gid_c_bytes, gid_c_len);

    uint8_t mac4[MAC_LEN];
    if (hmac_sha256_trunc16(tk_s, sizeof(tk_s), m4, m4_len, mac4) != 0) {
        free(m4);
        goto fail;
    }
    free(m4);

    if (write_n(cfd, nonce_s, NONCE_LEN) != 0) goto fail;
    if (write_n(cfd, mac4, MAC_LEN) != 0) goto fail;

    fprintf(stdout, "[server] handshake done\n");

    /* After both parties store nonce_C and nonce_S, derive shared seed:
       seed = h(K_PD || nonce_S || nonce_C || timestamp') */
    uint8_t shared_seed[SEED_LEN];
    if (derive_common_seed(kpd, nonce_s, nonce_c, ts2_ms, shared_seed) == 0) {
        hex_print("[server] shared seed", shared_seed, SEED_LEN);
    } else {
        fprintf(stderr, "[server] derive_common_seed failed\n");
    }

    /* cleanup */
    X509_free(cert_s);
    EVP_PKEY_free(priv_s);
    X509_free(cert_c);
    free(sig1);
    free(gid_c_bytes);
    return 0;

fail:
    if (cert_s) X509_free(cert_s);
    if (priv_s) EVP_PKEY_free(priv_s);
    if (cert_c) X509_free(cert_c);
    free(sig1);
    free(gid_c_bytes);
    return -1;
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <listen_port> <GID_S> <server_cert.pem> <server_key.pem> <logfile_or_->\n", argv[0]);
        fprintf(stderr, "Example: %s 9000 server01 server_cert.pem server_key.pem -\n", argv[0]);
        return 1;
    }

    uint16_t port = (uint16_t)atoi(argv[1]);
    const char *gid_s = argv[2];
    const char *cert_s = argv[3];
    const char *key_s  = argv[4];
    const char *log    = argv[5];

    if (strcmp(log, "-") != 0) {
        FILE *f = fopen(log, "a");
        if (f) {
            setvbuf(f, NULL, _IOLBF, 0);
            dup2(fileno(f), STDOUT_FILENO);
            dup2(fileno(f), STDERR_FILENO);
        }
    }

    int lfd = listen_tcp(port);
    if (lfd < 0) return 1;
    fprintf(stdout, "[server] listening on %u\n", port);

    while (1) {
        struct sockaddr_in cli;
        socklen_t slen = sizeof(cli);
        int cfd = accept(lfd, (struct sockaddr*)&cli, &slen);
        if (cfd < 0) {
            perror("accept");
            continue;
        }
        fprintf(stdout, "[server] client connected\n");

        /* avoid hang forever */
        set_sock_timeout(cfd, 10);

        server_handle(cfd, gid_s, cert_s, key_s);
        close(cfd);
    }

    close(lfd);
    return 0;
}
