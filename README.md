# Tiny AES KW in C

Lightweight AES Key Wrap implementation as per [RFC 3394](https://datatracker.ietf.org/doc/html/rfc3394).

It was written as part of an **[IEEE 802.1X/MKA (MACsec Key Agreement)](https://en.wikipedia.org/wiki/IEEE_802.1X)** implementation, where AES-KW is used for secure key transport.

Designed to be used with [tiny-AES-c](https://github.com/kokke/tiny-AES-c) library (only **AES-128** mode has been tested).

## Tests
`tests/` subdirectory contains a reference test against a RFC 3394 test vector for wrapping 128 bits of Key Data with a 128-bit KEK.

## API
```C
void AES_KW_init_ctx(struct AES_KW_ctx* ctx,
                     void (*aes_encrypt_callback)(uint8_t*),
                     void (*aes_decrypt_callback)(uint8_t*));

int AES_KW_wrap(const struct AES_KW_ctx* ctx,
                const uint8_t *plaintext, uint32_t pt_len,
                uint8_t *ciphertext);

int AES_KW_unwrap(const struct AES_KW_ctx* ctx,
                  const uint8_t *ciphertext, uint32_t ct_len,
                  uint8_t *plaintext);
```

## Usage
1. Specifically for `tiny-AES-C`: initialize the AES context with `AES_init_ctx()`.
2. Initialize the Key Wrap module using `AES_CMAC_init_ctx()` &#8211; pass the encrypt and decrypt callbacks.
3. Call `AES_KW_wrap()` and `AES_KW_wrap()` to wrapp or unwrap the key material.

## Acknowledgment
This project was inspired by [AES CMAC implementation](https://github.com/elektronika-ba/tiny-AES-CMAC-c) that uses the same AES library.

## Other implementations
- C
  - [Written for OpenSSL, contains RFC 5649 padding support](https://github.com/paulej/AESKeyWrap)
  - [hostap](https://git.w1.fi/cgit/hostap/tree/src/crypto/aes-wrap.c)
- C++
  - [Written for Crypto++, contains RFC 5649 padding support](https://github.com/ikluft/AESKeyWrap)
- Python
  - [Also contains RFC 5649 padding support](https://github.com/kurtbrose/aes_keywrap)
