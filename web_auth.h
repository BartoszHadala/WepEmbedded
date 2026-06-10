#ifndef WEP_AUTH_H_
#define WEP_AUTH_H_

#include "web_crypto.h"
#include "ring_buffer.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define AUTH_CHALLENGE_LEN  16u
#define AUTH_FRAME_MAX_LEN  64u
#define AUTH_BUF_SIZE      128u   /* backing memory for rx/tx ring buffers */

/* ------------------------------------------------------------------ */
/* Enums                                                               */
/* ------------------------------------------------------------------ */

typedef enum {
    FRAME_CHALLENGE  = 0x01,
    FRAME_RESPONSE   = 0x02,
    FRAME_AUTH_OK    = 0x03,
    FRAME_AUTH_FAIL  = 0x04,
    FRAME_DATA       = 0x05,
} FrameType;

typedef enum {
    AUTH_STATE_IDLE          = 0,
    AUTH_STATE_CHALLENGING   = 1,
    AUTH_STATE_AUTHENTICATED = 2,
    AUTH_STATE_FAILED        = 3,
} AuthState;

/* ------------------------------------------------------------------ */
/* Wire frame                                                          */
/*                                                                     */
/*  | type (1B) | iv (3B) | payloadLen (1B) | payload (N B) |         */
/* ------------------------------------------------------------------ */

typedef struct {
    FrameType type;
    uint8_t   iv[WEP_IV_LEN];
    uint8_t   payloadLen;
    uint8_t   payload[AUTH_FRAME_MAX_LEN];
} AuthFrame;

/* ------------------------------------------------------------------ */
/* Main context                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    WepCrypto  crypto;
    AuthState  state;
    uint8_t    challenge[AUTH_CHALLENGE_LEN];
    uint8_t    challengeLen;
    uint32_t   ivCounter;               /* simple IV source: incremented each tx */

    RingBuffer rxBuf;
    uint8_t    rxData[AUTH_BUF_SIZE];

    RingBuffer txBuf;
    uint8_t    txData[AUTH_BUF_SIZE];
} WepAuthContext;

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

void      WepAuth_Init          (WepAuthContext *ctx, const uint8_t key[WEP_KEY_LEN]);
void      WepAuth_Reset         (WepAuthContext *ctx);

bool      WepAuth_FeedByte      (WepAuthContext *ctx, uint8_t byte);
bool      WepAuth_GetTxByte     (WepAuthContext *ctx, uint8_t *byte);

bool      WepAuth_ParseFrame    (WepAuthContext *ctx, AuthFrame *frame);
bool      WepAuth_SendFrame     (WepAuthContext *ctx, const AuthFrame *frame);

AuthState WepAuth_Tick          (WepAuthContext *ctx);

/* internal — exposed for unit tests */
void      WepAuth_HandleChallenge  (WepAuthContext *ctx, const AuthFrame *frame);
void      WepAuth_HandleAuthResult (WepAuthContext *ctx, const AuthFrame *frame);
void      WepAuth_HandleData       (WepAuthContext *ctx, const AuthFrame *frame);

#ifdef __cplusplus
}
#endif
#endif /* WEP_AUTH_H_ */