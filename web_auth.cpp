#include "web_auth.h"
#include <string.h>
#include <assert.h>

/* Forward declaration for application-provided data handler */
extern void App_ProcessData(const uint8_t *data, size_t len);

/* ------------------------------------------------------------------ */
/* Internal helper: build a 3-byte IV from the counter                */
/* ------------------------------------------------------------------ */
static void build_iv(uint32_t counter, uint8_t iv[WEP_IV_LEN])
{
    // Rozbijamy 32-bitowy licznik na 3 bajty w formacie Little-Endian
    iv[0] = (uint8_t)(counter & 0xFF);
    iv[1] = (uint8_t)((counter >> 8) & 0xFF);
    iv[2] = (uint8_t)((counter >> 16) & 0xFF);
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

void WepAuth_Init(WepAuthContext *ctx, const uint8_t key[WEP_KEY_LEN])
{
    assert(ctx != NULL && key != NULL);

    // Kopiujemy klucz bazowy do podstruktury kryptograficznej
    memcpy(ctx->crypto.key, key, WEP_KEY_LEN);
    
    // Inicjalizacja licznika IV
    ctx->ivCounter = 0;

    // Inicjalizacja buforów pierścieniowych
    RingBuffer_Init(&ctx->rxBuf, ctx->rxData, AUTH_BUF_SIZE);
    RingBuffer_Init(&ctx->txBuf, ctx->txData, AUTH_BUF_SIZE);

    // Stan początkowy
    ctx->state = AUTH_STATE_IDLE;
}

void WepAuth_Reset(WepAuthContext *ctx)
{
    assert(ctx != NULL);

    // Czyszczenie buforów kołowych
    RingBuffer_Clear(&ctx->rxBuf);
    RingBuffer_Clear(&ctx->txBuf);

    // Reset stanu maszynki i wyzerowanie wyzwania (challenge)
    ctx->state = AUTH_STATE_IDLE;
    memset(ctx->challenge, 0, sizeof(ctx->challenge));
}

/* ------------------------------------------------------------------ */
/* UART integration                                                   */
/* ------------------------------------------------------------------ */

bool WepAuth_FeedByte(WepAuthContext *ctx, uint8_t byte)
{
    if (ctx == NULL) return false;
    // Wpychamy bajt odebrany z UART (np. z przerwania) do bufora RX
    return RingBuffer_PutChar(&ctx->rxBuf, (char)byte);
}

bool WepAuth_GetTxByte(WepAuthContext *ctx, uint8_t *byte)
{
    if (ctx == NULL || byte == NULL) return false;
    // Pobieramy bajt z bufora TX, aby wysłać go fizycznie przez UART
    return RingBuffer_GetChar(&ctx->txBuf, (char*)byte);
}

/* ------------------------------------------------------------------ */
/* Frame codec                                                        */
/* ------------------------------------------------------------------ */

bool WepAuth_ParseFrame(WepAuthContext *ctx, AuthFrame *frame)
{
    assert(ctx != NULL && frame != NULL);

    // Format ramki: | type(1) | iv(3) | payloadLen(1) | payload(N) |
    // Minimalny rozmiar nagłówka bez payloadu to 1 + 3 + 1 = 5 bajtów
    size_t bytesAvailable = RingBuffer_GetLength(&ctx->rxBuf);
    if (bytesAvailable < 5) {
        return false;
    }

    // Podglądamy długość payloadu (znajduje się na 4. indeksie nagłówka, czyli 5. bajt)
    uint8_t payloadLen;
    if (!RingBuffer_Peek(&ctx->rxBuf, 4, &payloadLen)) {
        return false;
    }

    // Sprawdzamy, czy w buforze jest już CAŁA ramka wraz z zadeklarowanym payloadem
    size_t totalFrameLen = 5 + payloadLen;
    if (bytesAvailable < totalFrameLen) {
        return false; // Czekamy na resztę danych
    }

    // Skoro mamy kompletną ramkę, możemy bezpiecznie skonsumować (wyciągnąć) ją z bufora
    {
        char typeRaw;
        RingBuffer_GetChar(&ctx->rxBuf, &typeRaw);
        frame->type = (FrameType)(uint8_t)typeRaw;
    }

    for (int i = 0; i < WEP_IV_LEN; i++) {
        RingBuffer_GetChar(&ctx->rxBuf, (char*)&frame->iv[i]);
    }

    RingBuffer_GetChar(&ctx->rxBuf, (char*)&frame->payloadLen);

    for (int i = 0; i < frame->payloadLen; i++) {
        RingBuffer_GetChar(&ctx->rxBuf, (char*)&frame->payload[i]);
    }

    return true;
}

bool WepAuth_SendFrame(WepAuthContext *ctx, const AuthFrame *frame)
{
    assert(ctx != NULL && frame != NULL);

    // Pakujemy pola struktury do bufora TX w odpowiedniej kolejności (wire order)
    if (!RingBuffer_PutChar(&ctx->txBuf, (char)frame->type)) return false;

    for (int i = 0; i < WEP_IV_LEN; i++) {
        if (!RingBuffer_PutChar(&ctx->txBuf, (char)frame->iv[i])) return false;
    }

    if (!RingBuffer_PutChar(&ctx->txBuf, (char)frame->payloadLen)) return false;

    for (int i = 0; i < frame->payloadLen; i++) {
        if (!RingBuffer_PutChar(&ctx->txBuf, (char)frame->payload[i])) return false;
    }

    return true;
}

/* ------------------------------------------------------------------ */
/* Internal handlers                                                  */
/* ------------------------------------------------------------------ */

void WepAuth_HandleChallenge(WepAuthContext *ctx, const AuthFrame *frame)
{
    assert(ctx != NULL && frame != NULL);

    // 1. Zapisujemy odebrane wyzwanie tekstowe do kontekstu
    // Zakładamy ochronę przed przepełnieniem rozmiaru tablicy challenge
    size_t copyLen = (frame->payloadLen > AUTH_CHALLENGE_LEN) ? AUTH_CHALLENGE_LEN : frame->payloadLen;
    memcpy(ctx->challenge, frame->payload, copyLen);
    ctx->challengeLen = (uint8_t)copyLen;

    // 2. Budujemy nowy wektor IV z inkrementowanego licznika
    uint8_t iv[WEP_IV_LEN];
    build_iv(ctx->ivCounter++, iv);

    // 3. Wrzucamy wygenerowane IV do struktury crypto
    memcpy(ctx->crypto.iv, iv, WEP_IV_LEN);

    // 4. Przygotowujemy ramkę odpowiedzi (odpowiedź ma typ AUTH_RESPONSE lub podobny z enuma)
    AuthFrame outFrame;
    outFrame.type = FRAME_RESPONSE;
    memcpy(outFrame.iv, iv, WEP_IV_LEN);
    
    // Rozmiar wyjściowy po szyfrowaniu WEP to plaintext + ICV (4 bajty)
    outFrame.payloadLen = ctx->challengeLen + 4; 

    // Szyfrujemy zapisany przed chwilą challenge i wynik pakujemy do payload ramki wyjściowej
    WepCrypto_Encrypt(&ctx->crypto, ctx->challenge, ctx->challengeLen, outFrame.payload);

    // 5. Wysyłamy spakowaną ramkę do bufora TX portu UART
    WepAuth_SendFrame(ctx, &outFrame);

    // 6. Zmieniamy stan na oczekiwanie na weryfikację
    ctx->state = AUTH_STATE_CHALLENGING;
}

void WepAuth_HandleAuthResult(WepAuthContext *ctx, const AuthFrame *frame)
{
    assert(ctx != NULL && frame != NULL);

    // Decyzja o zmianie stanu na podstawie zawartości ramki wynikowej
    // Często w payloadzie lub typie ramki siedzi informacja o sukcesie
    if (frame->type == FRAME_AUTH_OK) {
        ctx->state = AUTH_STATE_AUTHENTICATED;
    } else {
        ctx->state = AUTH_STATE_FAILED;
    }
}

void WepAuth_HandleData(WepAuthContext *ctx, const AuthFrame *frame)
{
    assert(ctx != NULL && frame != NULL);

    // Strażnik stanu – dane procesujemy tylko po udanej autoryzacji
    if (ctx->state != AUTH_STATE_AUTHENTICATED) {
        return;
    }

    // Do deszyfracji ładujemy IV, które przyszło bezpośrednio w nagłówku ramki danych
    memcpy(ctx->crypto.iv, frame->iv, WEP_IV_LEN);

    // Odszyfrowujemy dane (W WEP deszyfracja to to samo co szyfracja)
    // Tworzymy bufor na tekst jawny
    uint8_t decryptedPayload[256]; 
    
    // WepCrypto_Decrypt w WEP to funkcjonalnie wywołanie WepCrypto_Encrypt,
    // ponieważ algorytm bazuje na operacji XOR i sam odrzuca/weryfikuje ICV.
    // Jeśli Twoje API ma dedykowaną funkcję, zmień na WepCrypto_Decrypt.
    WepCrypto_Decrypt(&ctx->crypto, frame->payload, frame->payloadLen, decryptedPayload);

    // Przekazanie oczyszczonych danych (bez ICV) do warstwy aplikacji
    // Długość danych użytkowych to: długość payloadu - 4 bajty ICV
    size_t appDataLen = frame->payloadLen - 4;
    App_ProcessData(decryptedPayload, appDataLen); 
}

/* ------------------------------------------------------------------ */
/* State machine tick                                                 */
/* ------------------------------------------------------------------ */

AuthState WepAuth_Tick(WepAuthContext *ctx)
{
    if (ctx == NULL) return AUTH_STATE_IDLE;

    AuthFrame frame;

    // 1. Próbujemy sparsować ramkę. Jeśli jej nie ma (bufor niepełny) - nic nie robimy.
    if (!WepAuth_ParseFrame(ctx, &frame)) {
        return ctx->state;
    }

    // 2. Mamy pełną ramkę, kierujemy ją do odpowiedniego handlera w zależności od typu
    switch (frame.type) {
        case FRAME_CHALLENGE:
            WepAuth_HandleChallenge(ctx, &frame);
            break;

        case FRAME_AUTH_OK:
        case FRAME_AUTH_FAIL:
            WepAuth_HandleAuthResult(ctx, &frame);
            break;

        case FRAME_DATA:
            WepAuth_HandleData(ctx, &frame);
            break;

        default:
            // Nieznany typ ramki – ignorujemy i nie zmieniamy stanu
            break;
    }

    // 3. Zwracamy aktualny (potencjalnie zmieniony) stan maszyny
    return ctx->state;
}

/* ------------------------------------------------------------------ */
/* Application callback stub                                          */
/* ------------------------------------------------------------------ */

/* Default no-op — override in application code.                      */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
void App_ProcessData(const uint8_t *data, size_t len)
{
    (void)data;
    (void)len;
}