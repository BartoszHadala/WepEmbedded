#ifndef PC_FRAME_H_
#define PC_FRAME_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Constants                                                          */
/* ------------------------------------------------------------------ */

#define PC_WEP_IV_LEN        3u     //iV ma 3bajty
#define PC_FRAME_MAX_LEN     64u    //playload max 64bajty
#define PC_FRAME_HEADER_LEN  5u     //nagłówek 5bajtów

/*
 * Wire format:
 *
 * | type (1B) | iv (3B) | payloadLen (1B) | payload (N B) |
 */

/* ------------------------------------------------------------------ */
/* Frame types - muszą zgadzać się z embedded                         */
/* ------------------------------------------------------------------ */

typedef enum {
    PC_FRAME_CHALLENGE  = 0x01,     //komputer wysyła wyzwanie do urządzenia,
    PC_FRAME_RESPONSE   = 0x02,     //urządzenie odsyła zaszyfrowaną odpowiedź,
    PC_FRAME_AUTH_OK    = 0x03,     //komputer potwierdza, że autoryzacja się udała,
    PC_FRAME_AUTH_FAIL  = 0x04,     //komputer mówi, że autoryzacja się nie udała,
    PC_FRAME_DATA       = 0x05      //zwykłe dane po autoryzacji
} PcFrameType;

/* ------------------------------------------------------------------ */
/* Frame structure                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    PcFrameType type;                       //  typ ramki
    uint8_t     iv[PC_WEP_IV_LEN];          //  wektor IV
    uint8_t     payloadLen;                 //długość danych
    uint8_t     payload[PC_FRAME_MAX_LEN];  //dane ramki
} PcFrame;

bool PcFrame_Init(PcFrame *frame,
                  PcFrameType type,
                  const uint8_t iv[PC_WEP_IV_LEN],
                  const uint8_t *payload,
                  uint8_t payloadLen); //kopiuje gotową ramkę do struktury

bool PcFrame_Encode(const PcFrame *frame,
                    uint8_t *outBuf,
                    size_t outSize,
                    size_t *outLen); //zmienia strukture na bajty do wysłania przez serioal


bool PcFrame_Decode(const uint8_t *buf,
                    size_t len,
                    PcFrame *frame,
                    size_t *usedLen); //bierze bajty i próbuje z nich odtworzyć ramkę


size_t PcFrame_GetWireLength(const PcFrame *frame);

#ifdef __cplusplus
}
#endif

#endif 

