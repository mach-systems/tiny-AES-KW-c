/*
 * aes_kw.c
 *
 *  Created on: Oct 15, 2025
 *      Author: Karel Hevessy
 */

#include <string.h>
#include "aes_kw.h"


// Default Initial Value for AES Key Wrap
static const uint8_t DEFAULT_IV[8] = {
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
};

// Helper: XOR 64-bit value with counter
static void xor_with_counter(uint8_t *a, uint32_t t)
{
    a[7] ^= (t & 0xFF);
    a[6] ^= ((t >> 8) & 0xFF);
    a[5] ^= ((t >> 16) & 0xFF);
    a[4] ^= ((t >> 24) & 0xFF);
}

void AES_KW_init_ctx(struct AES_KW_ctx* ctx, void (*aes_encrypt_callback)(uint8_t*),
                     void (*aes_decrypt_callback)(uint8_t*))
{
    ctx->aes_encrypt_callback = aes_encrypt_callback;
    ctx->aes_decrypt_callback = aes_decrypt_callback;
}

int AES_KW_wrap(const struct AES_KW_ctx* ctx, const uint8_t *plaintext, uint32_t pt_len,
                uint8_t *ciphertext)
{
    uint8_t a[8];           // Integrity check register
    uint8_t b[16];          // AES input/output buffer
    uint32_t n;             // Number of 64-bit blocks
    uint32_t i, j, t;

    // Validate inputs
    if (!ctx || !plaintext || !ciphertext) return 0;
    if (pt_len < 16 || (pt_len % 8) != 0) return 0;

    n = pt_len / 8;

    // Initialize A <- IV
    (void) memcpy(a, DEFAULT_IV, 8);

    // Copy plaintext to output (we'll work in-place after initial copy)
    // R[1..n] <- P[1..n]
    (void) memcpy(&ciphertext[8], plaintext, pt_len);

    // Main wrap loop
    t = 0;
    for (j = 0; j < 6; j++) {
        for (i = 0; i < n; i++) {
            // B = AES(K, A | R[i])
            (void) memcpy(b, a, 8);
            (void) memcpy(&b[8], &ciphertext[8 + (i * 8)], 8);

            //AES_ECB_Encrypt(kek, b, b, kek_bits);
            ctx->aes_encrypt_callback(b);

            // A = MSB(64, B) ^ t
            t++;
            (void) memcpy(a, b, 8);
            xor_with_counter(a, t);

            // R[i] = LSB(64, B)
            (void) memcpy(&ciphertext[8 + (i * 8)], &b[8], 8);
        }
    }

    // Set C[0] = A
    (void) memcpy(ciphertext, a, 8);

    return pt_len + 8;
}

int AES_KW_unwrap(const struct AES_KW_ctx* ctx, const uint8_t *ciphertext, uint32_t ct_len,
                  uint8_t *plaintext)
{
    uint8_t a[8];           // Integrity check register
    uint8_t b[16];          // AES input/output buffer
    uint32_t n;             // Number of 64-bit blocks
    int32_t i, j;
    uint32_t t;
    uint32_t pt_len;

    // Validate inputs
    if (!ctx || !ciphertext || !plaintext) return 0;
    if (ct_len < 24 || (ct_len % 8) != 0) return 0;

    pt_len = ct_len - 8;
    n = pt_len / 8;

    // Initialize A <- C[0]
    (void) memcpy(a, ciphertext, 8);

    // Copy ciphertext blocks to output - R[1..n] <- C[1..n]
    (void) memcpy(plaintext, &ciphertext[8], pt_len);

    // Main unwrap loop (reverse order)
    t = 6 * n;
    for (j = 5; j >= 0; j--) {
        for (i = (n - 1); i >= 0; i--) {
            // B = AES-1(K, (A ^ t) | R[i])
            (void) memcpy(b, a, 8);
            xor_with_counter(b, t);
            (void) memcpy(&b[8], &plaintext[i * 8], 8);

            //AES_ECB_Decrypt(kek, b, b, kek_bits);
            ctx->aes_decrypt_callback(b);

            // A = MSB(64, B)
            (void) memcpy(a, b, 8);

            // R[i] = LSB(64, B)
            (void) memcpy(&plaintext[i * 8], &b[8], 8);

            t--;
        }
    }

    // Verify IV
    if (memcmp(a, DEFAULT_IV, 8) != 0) {
        // Integrity check failed - clear output and return error
        (void) memset(plaintext, 0, pt_len);
        return 0;
    }

    return pt_len;
}
