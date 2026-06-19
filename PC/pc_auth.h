#ifndef PC_AUTH_H
#define PC_AUTH_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "serial_port.h"
#include "pc_frame.h"
#include "wep_crypto.h"

/* ------------------------------------------------------------------ */
/* Stałe autoryzacji PC                                                */
/* ------------------------------------------------------------------ */

#define PC_AUTH_CHALLENGE_LEN   16
#define PC_AUTH_TIMEOUT_MS      3000
#define PC_AUTH_MAX_DATA_LEN    PC_FRAME_MAX_LEN

/* ------------------------------------------------------------------ */
/* Stany autoryzacji                                                   */
/* ------------------------------------------------------------------ */

typedef enum {
    PC_AUTH_STATE_IDLE = 0,
    PC_AUTH_STATE_CHALLENGE_SENT,
    PC_AUTH_STATE_AUTHENTICATED,
    PC_AUTH_STATE_FAILED
} PcAuthState;

/* ------------------------------------------------------------------ */
/* Kontekst autoryzacji PC                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    SerialPort *port;                              // port COM używany do komunikacji
    WepCrypto crypto;                             // kontekst szyfrowania WEP

    uint8_t challenge[PC_AUTH_CHALLENGE_LEN];     // challenge wysłany do embedded
    uint8_t challengeLen;                         // długość challenge

    uint32_t ivCounter;                           // licznik do generowania IV

    PcAuthState state;                            // aktualny stan autoryzacji
} PcAuthContext;

/* ------------------------------------------------------------------ */
/* Funkcje publiczne                                                   */
/* ------------------------------------------------------------------ */

bool PcAuth_Init(PcAuthContext *ctx,
                 SerialPort *port,
                 const uint8_t key[WEP_KEY_LEN]);

void PcAuth_Reset(PcAuthContext *ctx);

bool PcAuth_SendChallenge(PcAuthContext *ctx);

bool PcAuth_ReadFrame(PcAuthContext *ctx,
                      PcFrame *frame,
                      uint32_t timeoutMs);

bool PcAuth_VerifyResponse(PcAuthContext *ctx,
                           const PcFrame *frame);

bool PcAuth_SendResult(PcAuthContext *ctx,
                       bool success);

bool PcAuth_Authenticate(PcAuthContext *ctx);

bool PcAuth_SendData(PcAuthContext *ctx,
                     const uint8_t *data,
                     uint8_t dataLen);

bool PcAuth_ReceiveData(PcAuthContext *ctx,
                        uint8_t *outData,
                        size_t outSize,
                        size_t *outLen,
                        uint32_t timeoutMs);

PcAuthState PcAuth_GetState(const PcAuthContext *ctx);

#endif /* PC_AUTH_H */