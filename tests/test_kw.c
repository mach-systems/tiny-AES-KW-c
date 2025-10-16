/*
 * Test the implementation against RFC 3394 test vectors.
 */

#include <stdint.h>
#include <string.h>
#include "aes.h"
#include "aes_kw.h"


/**
 * Callback function that performs the actual AES encryption for AES KW.
 * @param  data Data to be encrypted
 * @retval None
 */
static void aes_kw_encrypt(uint8_t* data);

/**
 * Callback function that performs the actual AES decryption for AES KW.
 * @param  data Data to be decrypted
 * @retval None
 */
static void aes_kw_decrypt(uint8_t* data);


/**
 * For key wrapping / unwrapping
 */
static struct AES_ctx kwCtx;

/*
 * Reference result of the wrapping
 */
static const uint8_t wrapRefResult[24] = {0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
                                          0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
                                          0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5};


int main(void)
{
    uint8_t kek[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                       0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t wrap[24] = {0};
    uint8_t unwrap[16] = {0};
    
    AES_init_ctx(&kwCtx, &kek[0]);
    struct AES_KW_ctx aesKwCtx;
    AES_KW_init_ctx(&aesKwCtx, aes_kw_encrypt, aes_kw_decrypt);
    
    int ret1 = AES_KW_wrap(&aesKwCtx, key, 16, wrap);
    int ret2 = AES_KW_unwrap(&aesKwCtx, wrap, 24, unwrap);
    if ((24 == ret1) && (16 == ret2)
        && (memcmp(wrapRefResult, wrap, 24) == 0)
        && (memcmp(unwrap, key, 16) == 0))
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

void aes_kw_encrypt(uint8_t* data)
{
    AES_ECB_encrypt(&kwCtx, data);
}

void aes_kw_decrypt(uint8_t* data)
{
    AES_ECB_decrypt(&kwCtx, data);
}

