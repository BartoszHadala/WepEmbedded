#include "ring_buffer.h"
#include <assert.h>
#include <cstring>
#include <stdint.h>

/** Advance an index by 1 with wrap-around. */
#define RB_NEXT(idx, cap)  (((idx) + 1u) % (cap))

/** True when the buffer is completely full. */
#define RB_IS_FULL(rb)     ((rb)->length == (rb)->capacity)

/* ------------------------------------------------------------------ */


void RingBuffer_Init(RingBuffer *ringBuffer, void *dataBuffer, size_t dataBufferSize)
{
    assert(ringBuffer != NULL && dataBuffer != NULL);
    ringBuffer->dataBuffer = dataBuffer;
    ringBuffer->capacity = dataBufferSize;
    ringBuffer->length = 0;
    ringBuffer->head = 0;
    ringBuffer->tail = 0;
}

bool RingBuffer_Clear(RingBuffer *ringBuffer)
{
    if (ringBuffer == NULL) return false;
    if (ringBuffer->length > 0) {
        ringBuffer->head = 0;
        ringBuffer->tail = 0;
        ringBuffer->length = 0;
        return true;
    }
    return false;
}

bool RingBuffer_IsEmpty(RingBuffer const *ringBuffer)
{
    if (ringBuffer == NULL) return false;
    if (ringBuffer->length == 0) return true;
    return false;
}

size_t RingBuffer_GetLength(RingBuffer const *ringBuffer)
{
    if (ringBuffer == NULL) return 0;
    return ringBuffer->length;
}

size_t RingBuffer_GetCapacity(RingBuffer const *ringBuffer)
{
    if (ringBuffer == NULL) return 0;
    return ringBuffer->capacity;
}

bool RingBuffer_PutChar(RingBuffer *ringBuffer, char c)
{
    if (ringBuffer == NULL) return false;
    if (ringBuffer->length == ringBuffer->capacity) return false;
    ((char*)ringBuffer->dataBuffer)[ringBuffer->head] = c;
    ringBuffer->head = RB_NEXT(ringBuffer->head, ringBuffer->capacity);
    ringBuffer->length++;
    return true;
}

bool RingBuffer_GetChar(RingBuffer *ringBuffer, char *c)
{
    if (ringBuffer == NULL || c == NULL) return false;
    if (ringBuffer->length == 0) return false;
    *c = ((char*)ringBuffer->dataBuffer)[ringBuffer->tail];
    ringBuffer->tail = RB_NEXT(ringBuffer->tail, ringBuffer->capacity);
    ringBuffer->length--;
    return true;
}

bool RingBuffer_Peek(RingBuffer const *ringBuffer, size_t offset, uint8_t *out)
{
    if (ringBuffer == NULL || out == NULL) return false;
    if (offset >= ringBuffer->length) return false;
    *out = ((uint8_t*)ringBuffer->dataBuffer)[(ringBuffer->tail + offset) % ringBuffer->capacity];
    return true;
}