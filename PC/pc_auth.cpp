#include "pc_auth.h"
#include "serial_port.h"
#include "pc_frame.h"

#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Pomocnicza funkcja: budowanie IV z licznika                         */
/* ------------------------------------------------------------------ */

static void PcAuth_BuildIv(uint32_t counter, uint8_t iv[WEP_IV_LEN])
{
    if (iv == NULL) {
        return;
    }

    iv[0] = (uint8_t)(counter & 0xFF);
    iv[1] = (uint8_t)((counter >> 8) & 0xFF);
    iv[2] = (uint8_t)((counter >> 16) & 0xFF);
    // TODO:
    // 1. Sprawdzić, do czego służy IV w WEP
    // 2. Rozbić counter na 3 bajty
    // 3. Zapisać bajty do iv[0], iv[1], iv[2]
    // 4. Użyć tego IV przy szyfrowaniu ramek DATA albo RESPONSE


}

/* ------------------------------------------------------------------ */
/* Inicjalizacja kontekstu autoryzacji PC                              */
/* ------------------------------------------------------------------ */

bool PcAuth_Init(PcAuthContext *ctx,
                 SerialPort *port,
                 const uint8_t key[WEP_KEY_LEN])
{
    if (ctx == NULL || port == NULL || key == NULL) {
        return false;
    }

    // wyczyszczenie całej struktury kontekstu
    memset(ctx, 0, sizeof(PcAuthContext));

    // zapisanie portu COM
    ctx->port = port;

    // ustawienie klucza WEP
    WepCrypto_SetKey(&ctx->crypto, key);

    // wyzerowanie licznika IV
    ctx->ivCounter = 0;

    // ustawienie stanu początkowego
    ctx->state = PC_AUTH_STATE_IDLE;

    return true;
    // TODO:
    // 1. Sprawdzić, czy ctx != NULL
    // 2. Sprawdzić, czy port != NULL
    // 3. Sprawdzić, czy key != NULL
    // 4. Wyczyścić strukturę ctx
    // 5. Zapisać wskaźnik do portu COM
    // 6. Ustawić klucz WEP w ctx->crypto
    // 7. Wyzerować licznik IV
    // 8. Ustawić stan na PC_AUTH_STATE_IDLE
    // 9. Zwrócić true, jeśli wszystko się udało
}

/* ------------------------------------------------------------------ */
/* Reset autoryzacji                                                   */
/* ------------------------------------------------------------------ */

void PcAuth_Reset(PcAuthContext *ctx)
{
    if(ctx == NULL){
        return;
    }

    memset(ctx->challenge, 0, PC_AUTH_CHALLENGE_LEN);

    ctx->challengeLen = 0;
    ctx->ivCounter = 0;
    ctx->state = PC_AUTH_STATE_IDLE;
    // TODO:
    // 1. Sprawdzić, czy ctx != NULL
    // 2. Wyczyścić challenge
    // 3. Ustawić challengeLen = 0
    // 4. Wyzerować licznik IV
    // 5. Ustawić stan na PC_AUTH_STATE_IDLE
}

/* ------------------------------------------------------------------ */
/* Wysłanie challenge do embedded                                      */
/* ------------------------------------------------------------------ */

bool PcAuth_SendChallenge(PcAuthContext *ctx)
{
    if(ctx == NULL){
        return false;
    }

    if(!SerialPort_IsOpen(ctx->port)){
        return false;
    }

    ctx->challengeLen = PC_AUTH_CHALLENGE_LEN;

    for (uint8_t i = 0; i < ctx->challengeLen; i++) {
        ctx->challenge[i] = (uint8_t)(i + 1);
    }//najprostszy challenge

    // przygotowanie ramki FRAME_CHALLENGE bo challange musi być wysłany w formie ramki
    PcFrame frame;

    uint8_t iv[PC_WEP_IV_LEN] = {0, 0, 0}; //frame challange idzie jawnie więc kodujemy go 0



    if (!PcFrame_Init(&frame,
                      PC_FRAME_CHALLENGE,
                      iv,
                      ctx->challenge,
                      ctx->challengeLen)) {
        return false;
    }

    //gotowa ramka wysłana przez com
    uint8_t raw[PC_FRAME_HEADER_LEN + PC_FRAME_MAX_LEN]; 
    size_t rawLen = 0; //po wywołaniu funkcji tu zmieni się wartość

    //zmienia dane na bajty do wysłania przez serioal
    if(!PcFrame_Encode( &frame, 
                        raw, 
                        sizeof(raw), 
                        &rawLen)){
        return false;
    }

    //wysyłanie danych
    if (!SerialPort_Write(ctx->port, raw, rawLen)) {
        return false;
    }

    ctx->state = PC_AUTH_STATE_CHALLENGE_SENT;

    return true;
    // TODO:
    // 1. Sprawdzić, czy ctx != NULL
    // 2. Sprawdzić, czy port jest otwarty
    // 3. Przygotować challenge, np. 16 bajtów
    // 4. Zapisać challenge do ctx->challenge
    // 5. Ustawić ctx->challengeLen
    // 6. Przygotować ramkę PcFrame typu FRAME_CHALLENGE
    // 7. IV może być zerowe albo ustawione na 0
    // 8. Zakodować ramkę przez PcFrame_Encode
    // 9. Wysłać bajty przez SerialPort_Write
    // 10. Ustawić stan na PC_AUTH_STATE_CHALLENGE_SENT
    // 11. Zwrócić true, jeśli wysłanie się udało

    (void)ctx;

    return false;
}

/* ------------------------------------------------------------------ */
/* Odczyt jednej ramki z portu COM                                     */
/* ------------------------------------------------------------------ */

bool PcAuth_ReadFrame(PcAuthContext *ctx,
                      PcFrame *frame,
                      uint32_t timeoutMs)
{
    if (ctx == NULL || frame == NULL) {
        return false;
    }

    if (!SerialPort_IsOpen(ctx->port)) {
        return false;
    }

    uint8_t raw[PC_FRAME_HEADER_LEN + PC_FRAME_MAX_LEN];
    size_t received = 0;

    clock_t start = clock();

    // funkcja pomocnicza do sprawdzania timeoutu
    auto timeoutExpired = [&]() -> bool {
        if (timeoutMs == 0) {
            return false;
        }

        clock_t now = clock();
        uint32_t elapsedMs = (uint32_t)(((now - start) * 1000) / CLOCKS_PER_SEC);

        return elapsedMs >= timeoutMs;
    };

    // 1. Najpierw czytamy sam nagłówek ramki
    while (received < PC_FRAME_HEADER_LEN) {
        if (timeoutExpired()) {
            return false;
        }

        size_t n = SerialPort_Read(ctx->port,
                                   raw + received,
                                   PC_FRAME_HEADER_LEN - received);

        if (n > 0) {
            received += n;
        }
    }

    // 2. Z nagłówka odczytujemy długość payloadu
    uint8_t payloadLen = raw[4];

    if (payloadLen > PC_FRAME_MAX_LEN) {
        return false;
    }

    // 3. Obliczamy pełną długość ramki
    size_t wireLen = PC_FRAME_HEADER_LEN + payloadLen;

    // 4. Doczytujemy resztę ramki, jeśli payload istnieje
    while (received < wireLen) {
        if (timeoutExpired()) {
            return false;
        }

        size_t n = SerialPort_Read(ctx->port,
                                   raw + received,
                                   wireLen - received);

        if (n > 0) {
            received += n;
        }
    }

    // 5. Dekodujemy surowe bajty do struktury PcFrame
    size_t usedLen = 0;

    if (!PcFrame_Decode(raw, received, frame, &usedLen)) {
        return false;
    }

    return true;
    // TODO:
    // 1. Sprawdzić, czy ctx != NULL
    // 2. Sprawdzić, czy frame != NULL
    // 3. Sprawdzić, czy port jest otwarty
    // 4. Przygotować bufor tymczasowy na odebrane bajty
    // 5. Czytać dane z SerialPort_Read
    // 6. Najpierw odebrać minimum PC_FRAME_HEADER_LEN bajtów
    // 7. Z nagłówka odczytać payloadLen
    // 8. Obliczyć pełną długość ramki
    // 9. Doczytać brakujące bajty payloadu
    // 10. Wywołać PcFrame_Decode
    // 11. Obsłużyć timeoutMs
    // 12. Zwrócić true, jeśli udało się odebrać pełną ramkę

}

/* ------------------------------------------------------------------ */
/* Weryfikacja odpowiedzi od embedded                                  */
/* ------------------------------------------------------------------ */

bool PcAuth_VerifyResponse(PcAuthContext *ctx,
                           const PcFrame *frame)
{
    if(ctx == NULL || frame == NULL){
        return false;
    }

    if (frame->type != PC_FRAME_RESPONSE) {
        return false;
    }

    if (frame->payloadLen != ctx->challengeLen + WEP_ICV_LEN) {
        return false;
    }
    
    WepCrypto_SetIV(&ctx->crypto, frame->iv); 

    uint8_t decrypted[PC_AUTH_CHALLENGE_LEN]; //tablica na odszyfrowany challenge

    if (!WepCrypto_Decrypt(&ctx->crypto,
                           frame->payload,
                           frame->payloadLen,
                           decrypted)) {
        return false;
    }

    if (memcmp(decrypted, ctx->challenge, ctx->challengeLen) != 0) {
        return false;
    }

    return true;
    // TODO:
    // 1. Sprawdzić, czy ctx != NULL
    // 2. Sprawdzić, czy frame != NULL
    // 3. Sprawdzić, czy frame->type == FRAME_RESPONSE
    // 4. Ustawić IV w crypto na frame->iv
    // 5. Odszyfrować payload przez WepCrypto_Decrypt
    // 6. Sprawdzić, czy deszyfrowanie zakończyło się sukcesem
    // 7. Porównać odszyfrowane dane z ctx->challenge
    // 8. Jeśli dane są takie same, zwrócić true
    // 9. Jeśli dane się różnią, zwrócić false

}

/* ------------------------------------------------------------------ */
/* Wysłanie wyniku autoryzacji                                         */
/* ------------------------------------------------------------------ */

bool PcAuth_SendResult(PcAuthContext *ctx,
                       bool success)
{
    if(ctx==NULL){
        return false;
    }

    if(!SerialPort_IsOpen(ctx->port)){
        return false;
    }

    PcFrame frame;

    uint8_t iv[PC_WEP_IV_LEN] = {0, 0, 0};

    PcFrameType type;

    if (success == true) {
        type = PC_FRAME_AUTH_OK;
    } else {
        type = PC_FRAME_AUTH_FAIL;
    }

    if (!PcFrame_Init(&frame, type, iv, NULL, 0)) {
        return false;
    }

    uint8_t raw[PC_FRAME_HEADER_LEN + PC_FRAME_MAX_LEN];
    size_t rawLen = 0;

    if (!PcFrame_Encode(&frame, raw, sizeof(raw), &rawLen)) {
        return false;
    }

    if (!SerialPort_Write(ctx->port, raw, rawLen)) {
        return false;
    }

    if (success == true) {
        ctx->state = PC_AUTH_STATE_AUTHENTICATED;
    } else {
        ctx->state = PC_AUTH_STATE_FAILED;
    }

    return true;

    // TODO:
    // 1. Sprawdzić, czy ctx != NULL
    // 2. Sprawdzić, czy port jest otwarty
    // 3. Jeśli success == true, przygotować ramkę FRAME_AUTH_OK
    // 4. Jeśli success == false, przygotować ramkę FRAME_AUTH_FAIL
    // 5. Ramka może mieć payloadLen = 0
    // 6. Zakodować ramkę przez PcFrame_Encode
    // 7. Wysłać bajty przez SerialPort_Write
    // 8. Ustawić stan:
    //      - PC_AUTH_STATE_AUTHENTICATED, jeśli success == true
    //      - PC_AUTH_STATE_FAILED, jeśli success == false
    // 9. Zwrócić true, jeśli wysłanie się udało

}

/* ------------------------------------------------------------------ */
/* Pełna procedura autoryzacji                                         */
/* ------------------------------------------------------------------ */

bool PcAuth_Authenticate(PcAuthContext *ctx)
{
    if (ctx == NULL) {
        return false;
    }

    // 1. Wysyłamy challenge do embedded
    if (!PcAuth_SendChallenge(ctx)) {
        return false;
    }

    // 2. Czekamy na odpowiedź embedded
    PcFrame responseFrame;

    if (!PcAuth_ReadFrame(ctx,
                          &responseFrame,
                          PC_AUTH_TIMEOUT_MS)) {
        PcAuth_SendResult(ctx, false);
        return false;
    }

    // 3. Sprawdzamy, czy odpowiedź jest poprawna
    bool success = PcAuth_VerifyResponse(ctx, &responseFrame);

    // 4. Wysyłamy do embedded AUTH_OK albo AUTH_FAIL
    PcAuth_SendResult(ctx, success);

    // 5. Zwracamy wynik autoryzacji
    return success;
    // TODO:
    // 1. Sprawdzić, czy ctx != NULL
    // 2. Wywołać PcAuth_SendChallenge
    // 3. Odebrać ramkę odpowiedzi przez PcAuth_ReadFrame
    // 4. Sprawdzić odpowiedź przez PcAuth_VerifyResponse
    // 5. Wysłać wynik przez PcAuth_SendResult
    // 6. Jeśli odpowiedź była poprawna, zwrócić true
    // 7. Jeśli odpowiedź była błędna albo był timeout, zwrócić false

}

/* ------------------------------------------------------------------ */
/* Wysyłanie zaszyfrowanych danych po autoryzacji                      */
/* ------------------------------------------------------------------ */

bool PcAuth_SendData(PcAuthContext *ctx,
                     const uint8_t *data,
                     uint8_t dataLen)
{
    if (ctx == NULL) {
        return false;
    }

    if (dataLen > 0 && data == NULL) {
        return false;
    }

    if (!SerialPort_IsOpen(ctx->port)) {
        return false;
    }

    if (ctx->state != PC_AUTH_STATE_AUTHENTICATED) {
        return false;
    }

    if ((size_t)dataLen + WEP_ICV_LEN > PC_FRAME_MAX_LEN) {
        return false;
    }

    uint8_t iv[WEP_IV_LEN];

    // budujemy nowe IV z licznika i zwiększamy licznik o 1
    PcAuth_BuildIv(ctx->ivCounter++, iv);

    // ustawiamy IV w module szyfrowania WEP
    WepCrypto_SetIV(&ctx->crypto, iv);

    uint8_t encrypted[PC_FRAME_MAX_LEN];

    if (!WepCrypto_Encrypt(&ctx->crypto,
                           data,
                           dataLen,
                           encrypted)) {
        return false;
    }

     // po szyfrowaniu długość danych zwiększa się o 4 bajty ICV
    uint8_t encryptedLen = (uint8_t)(dataLen + WEP_ICV_LEN);

    PcFrame frame;

    if (!PcFrame_Init(&frame,
                      PC_FRAME_DATA,
                      iv,
                      encrypted,
                      encryptedLen)) {
        return false;
    }

    // tworzymy bufor na gotowe bajty do wysłania przez COM
    uint8_t raw[PC_FRAME_HEADER_LEN + PC_FRAME_MAX_LEN];
    size_t rawLen = 0;

    if (!PcFrame_Encode(&frame, raw, sizeof(raw), &rawLen)) {
        return false;
    }

    //wysyłamy bajty przez com
    if (!SerialPort_Write(ctx->port, raw, rawLen)) {
        return false;
    }

    return true;
    // TODO:
    // 1. Sprawdzić, czy ctx != NULL
    // 2. Sprawdzić, czy data != NULL, jeśli dataLen > 0
    // 3. Sprawdzić, czy ctx->state == PC_AUTH_STATE_AUTHENTICATED
    // 4. Sprawdzić, czy dataLen + WEP_ICV_LEN mieści się w PC_FRAME_MAX_LEN
    // 5. Wygenerować nowe IV przez PcAuth_BuildIv
    // 6. Ustawić IV w ctx->crypto
    // 7. Zaszyfrować dane przez WepCrypto_Encrypt
    // 8. Przygotować ramkę FRAME_DATA
    // 9. Zakodować ramkę przez PcFrame_Encode
    // 10. Wysłać bajty przez SerialPort_Write
    // 11. Zwrócić true, jeśli wszystko się udało
}

/* ------------------------------------------------------------------ */
/* Odbieranie zaszyfrowanych danych po autoryzacji                     */
/* ------------------------------------------------------------------ */

bool PcAuth_ReceiveData(PcAuthContext *ctx,
                        uint8_t *outData,
                        size_t outSize,
                        size_t *outLen,
                        uint32_t timeoutMs)
{
        // sprawdzamy, czy kontekst istnieje
    if (ctx == NULL) {
        return false;
    }

    // sprawdzamy, czy mamy gdzie zapisać odszyfrowane dane
    if (outData == NULL) {
        return false;
    }

    // sprawdzamy, czy mamy gdzie zapisać długość odebranych danych
    if (outLen == NULL) {
        return false;
    }

    // na start ustawiamy 0, żeby przy błędzie nie została stara wartość
    *outLen = 0;

    // dane można odbierać dopiero po udanej autoryzacji
    if (ctx->state != PC_AUTH_STATE_AUTHENTICATED) {
        return false;
    }

    // tworzymy strukturę na odebraną ramkę
    PcFrame frame;

    // odbieramy jedną pełną ramkę z portu COM
    if (!PcAuth_ReadFrame(ctx, &frame, timeoutMs)) {
        return false;
    }

    // sprawdzamy, czy odebrana ramka to faktycznie dane
    if (frame.type != PC_FRAME_DATA) {
        return false;
    }

    // zaszyfrowany payload musi mieć więcej niż samo ICV
    if (frame.payloadLen <= WEP_ICV_LEN) {
        return false;
    }

    // długość danych po odszyfrowaniu to payloadLen minus 4 bajty ICV
    size_t decryptedLen = frame.payloadLen - WEP_ICV_LEN;

    // sprawdzamy, czy dane po odszyfrowaniu zmieszczą się w outData
    if (decryptedLen > outSize) {
        return false;
    }

    // ustawiamy IV z odebranej ramki, bo nim była szyfrowana ta wiadomość
    WepCrypto_SetIV(&ctx->crypto, frame.iv);

    // tymczasowy bufor na odszyfrowane dane
    uint8_t decrypted[PC_FRAME_MAX_LEN];

    // odszyfrowujemy payload; funkcja sama sprawdza ICV
    if (!WepCrypto_Decrypt(&ctx->crypto,
                           frame.payload,
                           frame.payloadLen,
                           decrypted)) {
        return false;
    }

    // kopiujemy odszyfrowane dane do bufora wyjściowego
    memcpy(outData, decrypted, decryptedLen);

    // zapisujemy długość odebranych danych
    *outLen = decryptedLen;

    // wszystko się udało
    return true;
    // TODO:
    // 1. Sprawdzić, czy ctx != NULL
    // 2. Sprawdzić, czy outData != NULL
    // 3. Sprawdzić, czy outLen != NULL
    // 4. Sprawdzić, czy ctx->state == PC_AUTH_STATE_AUTHENTICATED
    // 5. Odebrać ramkę przez PcAuth_ReadFrame
    // 6. Sprawdzić, czy ramka ma typ FRAME_DATA
    // 7. Ustawić IV w ctx->crypto na IV z ramki
    // 8. Odszyfrować payload przez WepCrypto_Decrypt
    // 9. Sprawdzić, czy ICV było poprawne
    // 10. Sprawdzić, czy odszyfrowane dane mieszczą się w outSize
    // 11. Skopiować dane do outData
    // 12. Ustawić *outLen na długość odszyfrowanych danych
    // 13. Zwrócić true, jeśli wszystko się udało
}

/* ------------------------------------------------------------------ */
/* Pobranie aktualnego stanu autoryzacji                               */
/* ------------------------------------------------------------------ */

PcAuthState PcAuth_GetState(const PcAuthContext *ctx)
{
    if(ctx==NULL){
        return PC_AUTH_STATE_IDLE;
    }

    return ctx->state;
    // TODO:
    // 1. Sprawdzić, czy ctx != NULL
    // 2. Jeśli ctx == NULL, zwrócić PC_AUTH_STATE_IDLE
    // 3. W przeciwnym razie zwrócić ctx->state 
}

