#ifndef WEP_CRYPTO_H_
#define WEP_CRYPTO_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WEP_KEY_LEN      5u
#define WEP_IV_LEN       3u
#define WEP_ICV_LEN      4u
#define RC4_SBOX_SIZE  256u

/* RC4 state ---------------------------------------------------------- */

typedef struct {
    uint8_t S[RC4_SBOX_SIZE];
    uint8_t i;
    uint8_t j;
} RC4State;

/* WEP context -------------------------------------------------------- */

typedef struct {
    uint8_t  key[WEP_KEY_LEN];
    uint8_t  iv [WEP_IV_LEN];
    RC4State rc4;
} WepCrypto;

/* RC4 primitives ----------------------------------------------------- */

void    RC4_KSA    (RC4State *state, const uint8_t *key, size_t keyLen);
uint8_t RC4_PRGA   (RC4State *state, uint8_t byte);
void    RC4_Process(RC4State *state, uint8_t *buf, size_t len);

/* WEP helpers -------------------------------------------------------- */

void WepCrypto_SetKey(WepCrypto *ctx, const uint8_t key[WEP_KEY_LEN]);
void WepCrypto_SetIV (WepCrypto *ctx, const uint8_t iv [WEP_IV_LEN]);

bool WepCrypto_Encrypt(WepCrypto     *ctx,
                       const uint8_t *plaintext,  size_t plaintextLen,
                       uint8_t       *ciphertext);

bool WepCrypto_Decrypt(WepCrypto     *ctx,
                       const uint8_t *ciphertext, size_t ciphertextLen,
                       uint8_t       *plaintext);

/* CRC-32 ------------------------------------------------------------- */

uint32_t CRC32_Compute(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* WEP_CRYPTO_H_ */