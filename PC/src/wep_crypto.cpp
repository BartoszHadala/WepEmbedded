#include "wep_crypto.h"
#include <string.h>
#include <assert.h>

/* ------------------------------------------------------------------ */
/* CRC-32 - suma kontrolna dla WEP                                     */
/* ------------------------------------------------------------------ */

uint32_t CRC32_Compute(const uint8_t *data, size_t len)
{
    assert(data != NULL || len == 0);

    uint32_t crc = 0xFFFFFFFFu;

    for (size_t i = 0; i < len; i++) {
        crc ^= (uint32_t)data[i];

        for (int bit = 0; bit < 8; bit++) {
            if (crc & 1u) {
                crc = (crc >> 1) ^ 0xEDB88320u;
            } else {
                crc = crc >> 1;
            }
        }
    }

    return crc ^ 0xFFFFFFFFu;
}

/* ------------------------------------------------------------------ */
/* RC4 - inicjalizacja stanu                                           */
/* ------------------------------------------------------------------ */

void RC4_KSA(RC4State *state, const uint8_t *key, size_t keyLen)
{
    assert(state != NULL && key != NULL && keyLen > 0);

    for (size_t i = 0; i < 256; i++) {
        state->S[i] = (uint8_t)i;
    }

    uint8_t j = 0;

    for (size_t i = 0; i < 256; i++) {
        j = (uint8_t)(j + state->S[i] + key[i % keyLen]);

        uint8_t temp = state->S[i];
        state->S[i] = state->S[j];
        state->S[j] = temp;
    }

    state->i = 0;
    state->j = 0;
}

/* ------------------------------------------------------------------ */
/* RC4 - przetwarzanie jednego bajtu                                   */
/* ------------------------------------------------------------------ */

uint8_t RC4_PRGA(RC4State *state, uint8_t byte)
{
    assert(state != NULL);

    state->i = (uint8_t)(state->i + 1);
    state->j = (uint8_t)(state->j + state->S[state->i]);

    uint8_t temp = state->S[state->i];
    state->S[state->i] = state->S[state->j];
    state->S[state->j] = temp;

    uint8_t index = (uint8_t)(state->S[state->i] + state->S[state->j]);
    uint8_t keyByte = state->S[index];

    return byte ^ keyByte;
}

/* ------------------------------------------------------------------ */
/* RC4 - przetwarzanie bufora                                          */
/* ------------------------------------------------------------------ */

void RC4_Process(RC4State *state, uint8_t *buf, size_t len)
{
    assert(state != NULL && buf != NULL);

    for (size_t i = 0; i < len; i++) {
        buf[i] = RC4_PRGA(state, buf[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Pomocnicza funkcja: przygotowanie klucza IV + KEY                   */
/* ------------------------------------------------------------------ */

static void WepCrypto_ReloadRc4(WepCrypto *ctx)
{
    assert(ctx != NULL);

    uint8_t fullKey[WEP_IV_LEN + WEP_KEY_LEN];

    memcpy(fullKey, ctx->iv, WEP_IV_LEN);
    memcpy(fullKey + WEP_IV_LEN, ctx->key, WEP_KEY_LEN);

    RC4_KSA(&ctx->rc4, fullKey, WEP_IV_LEN + WEP_KEY_LEN);
}

/* ------------------------------------------------------------------ */
/* Ustawienie klucza WEP                                               */
/* ------------------------------------------------------------------ */

void WepCrypto_SetKey(WepCrypto *ctx, const uint8_t key[WEP_KEY_LEN])
{
    assert(ctx != NULL && key != NULL);

    memcpy(ctx->key, key, WEP_KEY_LEN);

    WepCrypto_ReloadRc4(ctx);
}

/* ------------------------------------------------------------------ */
/* Ustawienie IV                                                       */
/* ------------------------------------------------------------------ */

void WepCrypto_SetIV(WepCrypto *ctx, const uint8_t iv[WEP_IV_LEN])
{
    assert(ctx != NULL && iv != NULL);

    memcpy(ctx->iv, iv, WEP_IV_LEN);

    WepCrypto_ReloadRc4(ctx);
}

/* ------------------------------------------------------------------ */
/* Szyfrowanie WEP                                                     */
/* ------------------------------------------------------------------ */

bool WepCrypto_Encrypt(WepCrypto     *ctx,
                       const uint8_t *plaintext,
                       size_t         plaintextLen,
                       uint8_t       *ciphertext)
{
    if (ctx == NULL || plaintext == NULL || ciphertext == NULL) {
        return false;
    }

    WepCrypto_ReloadRc4(ctx);

    uint32_t icv = CRC32_Compute(plaintext, plaintextLen);

    memcpy(ciphertext, plaintext, plaintextLen);

    ciphertext[plaintextLen + 0] = (uint8_t)(icv & 0xFF);
    ciphertext[plaintextLen + 1] = (uint8_t)((icv >> 8) & 0xFF);
    ciphertext[plaintextLen + 2] = (uint8_t)((icv >> 16) & 0xFF);
    ciphertext[plaintextLen + 3] = (uint8_t)((icv >> 24) & 0xFF);

    size_t totalLen = plaintextLen + WEP_ICV_LEN;

    for (size_t i = 0; i < totalLen; i++) {
        ciphertext[i] = RC4_PRGA(&ctx->rc4, ciphertext[i]);
    }

    return true;
}

/* ------------------------------------------------------------------ */
/* Deszyfrowanie WEP                                                   */
/* ------------------------------------------------------------------ */

bool WepCrypto_Decrypt(WepCrypto     *ctx,
                       const uint8_t *ciphertext,
                       size_t         ciphertextLen,
                       uint8_t       *plaintext)
{
    if (ctx == NULL || ciphertext == NULL || plaintext == NULL) {
        return false;
    }

    if (ciphertextLen <= WEP_ICV_LEN) {
        return false;
    }

    WepCrypto_ReloadRc4(ctx);

    size_t plaintextLen = ciphertextLen - WEP_ICV_LEN;

    for (size_t i = 0; i < plaintextLen; i++) {
        plaintext[i] = RC4_PRGA(&ctx->rc4, ciphertext[i]);
    }

    uint8_t receivedIcvBytes[WEP_ICV_LEN];

    for (size_t i = 0; i < WEP_ICV_LEN; i++) {
        receivedIcvBytes[i] = RC4_PRGA(&ctx->rc4, ciphertext[plaintextLen + i]);
    }

    uint32_t computedIcv = CRC32_Compute(plaintext, plaintextLen);

    uint32_t receivedIcv = (uint32_t)receivedIcvBytes[0]
                         | ((uint32_t)receivedIcvBytes[1] << 8)
                         | ((uint32_t)receivedIcvBytes[2] << 16)
                         | ((uint32_t)receivedIcvBytes[3] << 24);

    return computedIcv == receivedIcv;
}