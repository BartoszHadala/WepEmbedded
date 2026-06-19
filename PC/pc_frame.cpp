#include "pc_frame.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/* Frame initialization                                                */
/* ------------------------------------------------------------------ */

bool PcFrame_Init(PcFrame *frame,
                  PcFrameType type,
                  const uint8_t iv[PC_WEP_IV_LEN],
                  const uint8_t *payload,
                  uint8_t payloadLen)
{

    if(frame==NULL){
        return false;
    }

    if(payloadLen>PC_FRAME_MAX_LEN){
        return false;
    }

    frame->type = type;
    
    if(iv!=NULL){
        memcpy(frame->iv, iv, PC_WEP_IV_LEN);
    }

    if(iv==NULL){
        memset(frame->iv, 0, PC_WEP_IV_LEN);
    }

    frame->payloadLen=payloadLen;

    if(payloadLen > 0){
        memcpy(frame->payload, payload,  payloadLen);
    }
    
    return true;
    // TODO:
    // 1. Sprawdzić, czy frame != NULL
    // 2. Sprawdzić, czy payloadLen nie przekracza PC_FRAME_MAX_LEN
    // 3. Ustawić typ ramki
    // 4. Skopiować IV, jeśli iv != NULL
    // 5. Jeśli iv == NULL, wyzerować IV
    // 6. Ustawić payloadLen
    // 7. Skopiować payload, jeśli payloadLen > 0
    // 8. Zwrócić true, jeśli wszystko się udało

}

/* ------------------------------------------------------------------ */
/* Encode frame to raw bytes                                           */
/* ------------------------------------------------------------------ */

/*
outBuf[0] = type
outBuf[1] = iv[0]
outBuf[2] = iv[1]
outBuf[3] = iv[2]
outBuf[4] = payloadLen
outBuf[5] = payload[0]
outBuf[6] = payload[1]
outBuf[7] = payload[2]
...
*/
bool PcFrame_Encode(const PcFrame *frame,
                    uint8_t *outBuf,
                    size_t outSize,
                    size_t *outLen)
{

    if(frame == NULL || outBuf == NULL || outLen == NULL){
        return false;
    }

    if (frame->payloadLen > PC_FRAME_MAX_LEN) {
        return false;
    } //sprawdzam drugi raz czy się mieści w zkresie

    size_t outBufSize = PC_FRAME_HEADER_LEN + frame->payloadLen; //ile danych do wpisania

    if(outBufSize > outSize){
        return false;
    } //jeśli się nie pieści to false

    //wpisywanie nagłówka
    outBuf[0] = frame->type;
    outBuf[1] = frame->iv[0];
    outBuf[2] = frame->iv[1];
    outBuf[3] = frame->iv[2];
    outBuf[4] = frame->payloadLen;

    //wpisywanie danych
    if(frame->payloadLen > 0){
        memcpy(outBuf + PC_FRAME_HEADER_LEN, frame->payload, frame->payloadLen);
    }
    

    //ile danych zostało wysłane
    *outLen = outBufSize;

    return true;

    // TODO:
    // 1. Sprawdzić, czy frame != NULL
    // 2. Sprawdzić, czy outBuf != NULL
    // 3. Sprawdzić, czy outLen != NULL
    // 4. Sprawdzić, czy frame->payloadLen nie przekracza PC_FRAME_MAX_LEN
    // 5. Obliczyć długość ramki na kablu:
    //      wireLen = PC_FRAME_HEADER_LEN + frame->payloadLen
    // 6. Sprawdzić, czy outSize >= wireLen
    // 7. Wpisać type do outBuf[0]
    // 8. Skopiować IV do outBuf[1], outBuf[2], outBuf[3]
    // 9. Wpisać payloadLen do outBuf[4]
    // 10. Skopiować payload do outBuf[5...]
    // 11. Ustawić *outLen = wireLen
    // 12. Zwrócić true, jeśli wszystko się udało
}

/* ------------------------------------------------------------------ */
/* Decode raw bytes to frame                                           */
/* ------------------------------------------------------------------ */

bool PcFrame_Decode(const uint8_t *buf,
                    size_t len,
                    PcFrame *frame,
                    size_t *usedLen)
{
    if (buf == NULL || frame == NULL || usedLen == NULL) {
        return false;
    }

    // jeśli nie ma nawet pełnego nagłówka
    if (len < PC_FRAME_HEADER_LEN) {
        return false;
    }

    // odczyt długości payloadu z nagłówka
    uint8_t payloadLen = buf[4];

    // sprawdzenie, czy payloadLen mieści się w zakresie
    if (payloadLen > PC_FRAME_MAX_LEN) {
        return false;
    }

    // obliczenie długości całej ramki
    size_t wireLen = PC_FRAME_HEADER_LEN + payloadLen;

    // jeśli nie ma jeszcze całej ramki
    if (len < wireLen) {
        return false;
    }

    // odczyt typu ramki
    frame->type = (PcFrameType)buf[0];

    // odczyt IV
    frame->iv[0] = buf[1];
    frame->iv[1] = buf[2];
    frame->iv[2] = buf[3];

    // ustawienie długości payloadu
    frame->payloadLen = payloadLen;

    // skopiowanie payloadu
    if (payloadLen > 0) {
        memcpy(frame->payload, buf + PC_FRAME_HEADER_LEN, payloadLen);
    }

    // informacja, ile bajtów zużyto z bufora
    *usedLen = wireLen;

    return true;

    // TODO: 
    // 1. Sprawdzić, czy buf != NULL 
    // 2. Sprawdzić, czy frame != NULL 
    // 3. Sprawdzić, czy usedLen != NULL 
    // 4. Sprawdzić, czy len >= PC_FRAME_HEADER_LEN 
    // jeśli nie, to nie ma nawet pełnego nagłówka 
    // 5. Odczytać payloadLen z buf[4] 
    // 6. Sprawdzić, czy payloadLen <= PC_FRAME_MAX_LEN 
    // 7. Obliczyć długość całej ramki: 
    // wireLen = PC_FRAME_HEADER_LEN + payloadLen 
    // 8. Sprawdzić, czy len >= wireLen 
    // jeśli nie, to nie ma jeszcze całej ramki 
    // 9. Odczytać type z buf[0] 
    // 10. Skopiować IV z buf[1], buf[2], buf[3] do frame->iv 
    // 11. Ustawić frame->payloadLen = payloadLen 
    // 12. Skopiować payload z buf[5...] do frame->payload 
    // 13. Ustawić *usedLen = wireLen 
    // 14. Zwrócić true, jeśli udało się odczytać całą ramkę
}

/* ------------------------------------------------------------------ */
/* Get wire length                                                     */
/* ------------------------------------------------------------------ */

size_t PcFrame_GetWireLength(const PcFrame *frame)
{

    if(frame == NULL){
        return 0;
    }

    return PC_FRAME_HEADER_LEN + frame -> payloadLen;
    // TODO:
    // 1. Sprawdzić, czy frame != NULL
    // 2. Zwrócić PC_FRAME_HEADER_LEN + frame->payloadLen

}
