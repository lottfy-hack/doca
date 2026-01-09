# TXLKS-based handshake demo (your protocol)

This is a small, self-contained C implementation of the 4-message protocol you described, using:

- **Sign**: `Sign_{Priv}(GID || timestamp)` with SHA-256 + EVP signatures
- **ENC**: `ENC_{Pub_C}(K_PD)` using RSA-OAEP
- **MAC**: `MAC_{tk}(...)` implemented as HMAC-SHA256 truncated to 128-bit
- **TXLKS**: TinyMT32 + XSadd + rotate/add (Algorithm 1 in IEEE TDSC 2024)
  - Parameters `r1=3`, `r2=5` (paper Section VII-A)

## Build

Requires OpenSSL dev headers.

```bash
cd txlks_proto
make
```

## Generate demo certs/keys

```bash
# Client
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client_key.pem
openssl req -new -x509 -key client_key.pem -subj "/CN=client" -days 365 -out client_cert.pem

# Server
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out server_key.pem
openssl req -new -x509 -key server_key.pem -subj "/CN=server" -days 365 -out server_cert.pem
```

## Run

Terminal 1:

```bash
./server 9000 GID_SERVER server_cert.pem server_key.pem
```

Terminal 2:

```bash
./client 127.0.0.1 9000 GID_CLIENT client_cert.pem client_key.pem GID_SERVER
```

If everything verifies, you will see both sides print the derived `tk_C` and `tk_S` (hex) and MAC verification success.

## Message formats (on the wire)

All variable-length fields are length-prefixed.

1. **Client -> Server**
   - u16 gid_len || gid
   - u32 cert_len || cert_pem_bytes
   - u16 sig_len || sig (over gid||ts)
   - u64 timestamp_ms

2. **Server -> Client**
   - u16 gid_len || gid
   - u32 cert_len || cert_pem_bytes
   - u16 enc_len || RSA_OAEP(Pub_C, K_PD)
   - u16 sig_len || sig (over enc||ts')
   - u64 timestamp'_ms

3. **Client -> Server**
   - nonce_C (16 bytes)
   - mac_C (16 bytes) = HMAC(tk_C, nonce_C||GID_S||GID_C)[0..15]

4. **Server -> Client**
   - nonce_S (16 bytes)
   - mac_S (16 bytes) = HMAC(tk_S, nonce_C||nonce_S||GID_S||GID_C)[0..15]

## Where TXLKS is used

- Client:
  - seed_C = SHA256(K_PD || nonce_C || timestamp')
  - tk_C = TXLKS(seed_C)

- Server:
  - seed_S = SHA256(K_PD || nonce_S || timestamp')
  - tk_S = TXLKS(seed_S)

## Shared seed after both nonces are known

After Msg4 is verified, both sides have stored `nonce_C` and `nonce_S`.
The demo additionally derives and prints a *shared seed* that you can use as
the seed for a key sequence:

```
shared_seed = SHA256(K_PD || nonce_S || nonce_C || timestamp')
```

See `derive_common_seed(...)` in `common.c` and the final output of `client` and
`server`.

TXLKS(·) is implemented in `txlks.c`.
