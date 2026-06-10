#ifndef RING_BUFFER_H_
#define RING_BUFFER_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void   *dataBuffer;
    size_t  capacity;
    size_t  length;
    size_t  head;
    size_t  tail;
} RingBuffer;

void   RingBuffer_Init       (RingBuffer *ringBuffer, void *dataBuffer, size_t dataBufferSize);
bool   RingBuffer_Clear      (RingBuffer *ringBuffer);
bool   RingBuffer_IsEmpty    (RingBuffer const *ringBuffer);
size_t RingBuffer_GetLength  (RingBuffer const *ringBuffer);
size_t RingBuffer_GetCapacity(RingBuffer const *ringBuffer);
bool   RingBuffer_PutChar    (RingBuffer *ringBuffer, char c);
bool   RingBuffer_GetChar    (RingBuffer *ringBuffer, char *c);
bool   RingBuffer_Peek       (RingBuffer const *ringBuffer, size_t offset, uint8_t *out);

#ifdef __cplusplus
}
#endif
#endif /* RING_BUFFER_H_ */
