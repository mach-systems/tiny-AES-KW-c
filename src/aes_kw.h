/*
 * aes_kw.h
 *
 *  Created on: Oct 15, 2025
 *      Author: Karel Hevessy
 *
 * AES Key Wrap according to RFC 3394.
 *
 */

#ifndef INC_AES_KW_H_
#define INC_AES_KW_H_

#include <stdint.h>


/**
 * Key Wrap context - encrypt / decrypt callback
 */
struct AES_KW_ctx
{
    void (*aes_encrypt_callback)(uint8_t*);
    void (*aes_decrypt_callback)(uint8_t*);
};


/**
 * Initialize context for AES KW.
 * @param  ctx Context with encryption / decryption functions
 * @param  aes_encrypt_callback Function to be called for AES ECB encryption
 * @param  aes_decrypt_callback Function to be called for AES ECB decryption
 * @retval None
 */
void AES_KW_init_ctx(struct AES_KW_ctx* ctx, void (*aes_encrypt_callback)(uint8_t*),
                     void (*aes_decrypt_callback)(uint8_t*));

/**
 * AES Key Wrap.
 * @param ctx         Context with encryption/decryption functions
 * @param plaintext   Key to wrap (must be multiple of 8 bytes)
 * @param pt_len      Plaintext length in bytes (must be >= 16 and multiple of 8)
 * @param ciphertext  Output buffer (must be pt_len + 8 bytes)
 * @return            Length of wrapped key in bytes, or 0 on error
 */
int AES_KW_wrap(const struct AES_KW_ctx* ctx, const uint8_t *plaintext, uint32_t pt_len,
                uint8_t *ciphertext);

/**
 * AES Key Unwrap.
 * @param ctx         Context with encryption/decryption functions
 * @param ciphertext  Wrapped key
 * @param ct_len      Ciphertext length in bytes (must be >= 24 and multiple of 8)
 * @param plaintext   Output buffer (must be ct_len - 8 bytes)
 * @return            Length of unwrapped key in bytes, or 0 on error/integrity failure
 */
int AES_KW_unwrap(const struct AES_KW_ctx* ctx, const uint8_t *ciphertext, uint32_t ct_len,
                  uint8_t *plaintext);



#endif /* INC_AES_KW_H_ */
