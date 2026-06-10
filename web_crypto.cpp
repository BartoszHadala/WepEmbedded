#include "web_crypto.h"
#include <string.h>
#include <assert.h>

/* ------------------------------------------------------------------ */
/* CRC-32  (IEEE 802.3, poly = 0xEDB88320, little-endian)             */
/* ------------------------------------------------------------------ */

uint32_t CRC32_Compute(const uint8_t *data, size_t len)
{
    assert(data != NULL || len == 0);
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint32_t)data[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ ((crc & 1u) ? 0xEDB88320u : 0u);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/* ------------------------------------------------------------------ */
/* RC4                                                                 */
/* ------------------------------------------------------------------ */

void RC4_KSA(RC4State *state, const uint8_t *key, size_t keyLen)
{
    assert(state != NULL && key != NULL);
    
    // Krok 1: Inicjalizacja tablicy S wewnątrz struktury state
    for (size_t i = 0; i < 256; i++) {
        state->S[i] = i;
    }

    size_t j = 0;
    // Krok 2: Mieszanie tablicy (poprawione j++ na i++)
    for (size_t i = 0; i < 256; i++) {
        j = (j + state->S[i] + key[i % keyLen]) & 0xFF;
        
        // Zamiana elementów w strukturze state
        uint8_t temp = state->S[i];
        state->S[i] = state->S[j];
        state->S[j] = temp;
    }
    
    // Krok 3: KLUCZOWE DLA PRGA
    // Zerujemy indeksy stanu, aby PRGA wystartowało od początku tablicy
    state->i = 0;
    state->j = 0;
}

uint8_t RC4_PRGA(RC4State *state, uint8_t byte)
{
    assert(state != NULL);
    
    // 1. Inkrementacja indeksów (inkrementacja uint8_t automatycznie robi modulo 256)
    state->i = (state->i + 1) & 0xFF;
    state->j = (state->j + state->S[state->i]) & 0xFF;
    
    // 2. Zamiana elementów w tablicy S (Swap)
    uint8_t temp = state->S[state->i];
    state->S[state->i] = state->S[state->j];
    state->S[state->j] = temp;
    
    // 3. Wyznaczenie bajtu strumienia klucza
    uint8_t t = (state->S[state->i] + state->S[state->j]) & 0xFF;
    uint8_t keystream_byte = state->S[t];
    
    // 4. Zwrócenie wyniku operacji XOR na podanym bajcie danych
    return byte ^ keystream_byte;
}

/* ------------------------------------------------------------------ */
/* WEP helpers                                                         */
/* ------------------------------------------------------------------ */

void WepCrypto_SetKey(WepCrypto *ctx, const uint8_t key[WEP_KEY_LEN])
{
// 1. Sprawdzenie poprawności wskaźników
    assert(ctx != NULL && key != NULL);

    // 2. Skopiowanie klucza bazowego do struktury
    memcpy(ctx->key, key, WEP_KEY_LEN);

    // 3. Przygotowanie bufora na pełny klucz RC4 (IV + KEY)
    uint8_t full_rc4_key[WEP_IV_LEN + WEP_KEY_LEN];

    // Skopiowanie IV na początek bufora
    memcpy(full_rc4_key, ctx->iv, WEP_IV_LEN);
    
    // Doklejenie klucza zaraz za IV
    memcpy(full_rc4_key + WEP_IV_LEN, ctx->key, WEP_KEY_LEN);

    // 4. Inicjalizacja stanu RC4 połączonym kluczem
    RC4_KSA(&(ctx->rc4), full_rc4_key, WEP_IV_LEN + WEP_KEY_LEN);}

void WepCrypto_SetIV(WepCrypto *ctx, const uint8_t iv[WEP_IV_LEN])
{
    assert(ctx != NULL && iv != NULL);
    memcpy(ctx->iv, iv, WEP_IV_LEN);

    uint8_t full_rc4_key[WEP_IV_LEN + WEP_KEY_LEN];
    memcpy(full_rc4_key, ctx->iv, WEP_IV_LEN);
    memcpy(full_rc4_key + WEP_IV_LEN, ctx->key, WEP_KEY_LEN);
    RC4_KSA(&ctx->rc4, full_rc4_key, WEP_IV_LEN + WEP_KEY_LEN);
}

bool WepCrypto_Encrypt(WepCrypto     *ctx,
                       const uint8_t *plaintext,  size_t plaintextLen,
                       uint8_t       *ciphertext)
{
    // Sprawdzenie poprawności wskaźników
    if (ctx == NULL || plaintext == NULL || ciphertext == NULL) {
        return false;
    }

    // Krok 0: Bardzo ważny! Re-inicjalizacja stanu RC4 (KSA) przed szyfrowaniem pakietu.
    // Gwarantuje to, że używamy świeżego stanu powiązanego z IV + KEY dla tego konkretnego pakietu.
    WepCrypto_SetKey(ctx, ctx->key);

    // Krok 1: Obliczenie ICV = CRC32(plaintext)
    uint32_t icv = CRC32_Compute(plaintext, plaintextLen);

    // Krok 2: Skopiowanie tekstu jawnego do bufora wyjściowego (ciphertext)
    memcpy(ciphertext, plaintext, plaintextLen);

    // Krok 2b: Doklejenie ICV na koniec w formacie Little-Endian
    // Zapisujemy 32-bitową wartość bajt po bajcie, od najmniej znaczącego (LSB)
    ciphertext[plaintextLen + 0] = (uint8_t)(icv & 0xFF);
    ciphertext[plaintextLen + 1] = (uint8_t)((icv >> 8) & 0xFF);
    ciphertext[plaintextLen + 2] = (uint8_t)((icv >> 16) & 0xFF);
    ciphertext[plaintextLen + 3] = (uint8_t)((icv >> 24) & 0xFF);

    // Krok 3: Szyfrowanie całości (plaintext + ICV) bajt po bajcie przy użyciu RC4_PRGA
    size_t totalLen = plaintextLen + WEP_ICV_LEN;
    for (size_t i = 0; i < totalLen; i++) {
        ciphertext[i] = RC4_PRGA(&(ctx->rc4), ciphertext[i]);
    }

    return true;
}

/* ------------------------------------------------------------------ */
/* RC4_Process                                                         */
/* ------------------------------------------------------------------ */

void RC4_Process(RC4State *state, uint8_t *buf, size_t len)
{
    assert(state != NULL && buf != NULL);
    for (size_t i = 0; i < len; i++) {
        buf[i] = RC4_PRGA(state, buf[i]);
    }
}

/* ------------------------------------------------------------------ */
/* WepCrypto_Decrypt                                                   */
/* ------------------------------------------------------------------ */

bool WepCrypto_Decrypt(WepCrypto     *ctx,
                       const uint8_t *ciphertext, size_t ciphertextLen,
                       uint8_t       *plaintext)
{
    if (ctx == NULL || ciphertext == NULL || plaintext == NULL) {
        return false;
    }
    if (ciphertextLen <= WEP_ICV_LEN) {
        return false;
    }

    /* Re-seed RC4 with current IV + key */
    WepCrypto_SetKey(ctx, ctx->key);

    size_t plaintextLen = ciphertextLen - WEP_ICV_LEN;

    /* Decrypt plaintext portion */
    for (size_t i = 0; i < plaintextLen; i++) {
        plaintext[i] = RC4_PRGA(&ctx->rc4, ciphertext[i]);
    }

    /* Decrypt ICV portion */
    uint8_t icvBuf[WEP_ICV_LEN];
    for (size_t i = 0; i < WEP_ICV_LEN; i++) {
        icvBuf[i] = RC4_PRGA(&ctx->rc4, ciphertext[plaintextLen + i]);
    }

    /* Verify ICV */
    uint32_t computed_icv = CRC32_Compute(plaintext, plaintextLen);
    uint32_t received_icv = (uint32_t)icvBuf[0]
                          | ((uint32_t)icvBuf[1] << 8)
                          | ((uint32_t)icvBuf[2] << 16)
                          | ((uint32_t)icvBuf[3] << 24);

    return (computed_icv == received_icv);
}