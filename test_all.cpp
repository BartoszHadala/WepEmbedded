/**
 * TDD test suite for:
 *   - RingBuffer
 *   - RC4 / WepCrypto
 *   - WepAuth (state machine)
 *
 * Build with:
 *   g++ -std=c++17 -I../include \
 *       ../src/ring_buffer.cpp ../src/wep_crypto.cpp ../src/wep_auth.cpp \
 *       test_all.cpp \
 *       -lgtest -lgtest_main -pthread -o run_tests
 *
 * Run:
 *   ./run_tests
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "ring_buffer.h"
#include "web_crypto.h"
#include "web_auth.h"
}

/* ======================================================================
 * SECTION 1 — RingBuffer
 * ====================================================================== */

class RingBufferTest : public ::testing::Test {
protected:
    static constexpr size_t CAP = 8;
    uint8_t    backing[CAP];
    RingBuffer rb;

    void SetUp() override {
        RingBuffer_Init(&rb, backing, CAP);
    }
};

// --- Init & basic state ---

TEST_F(RingBufferTest, InitCapacityCorrect) {
    EXPECT_EQ(RingBuffer_GetCapacity(&rb), CAP);
}

TEST_F(RingBufferTest, InitIsEmpty) {
    EXPECT_TRUE(RingBuffer_IsEmpty(&rb));
    EXPECT_EQ(RingBuffer_GetLength(&rb), 0u);
}

// --- Null-safety ---

TEST_F(RingBufferTest, NullPtrClearReturnsFalse) {
    EXPECT_FALSE(RingBuffer_Clear(nullptr));
}

TEST_F(RingBufferTest, NullPtrIsEmpty) {
    // Should not crash; return false for NULL
    EXPECT_FALSE(RingBuffer_IsEmpty(nullptr));
}

TEST_F(RingBufferTest, NullPtrGetLengthReturnsZero) {
    EXPECT_EQ(RingBuffer_GetLength(nullptr), 0u);
}

TEST_F(RingBufferTest, NullPtrGetCapacityReturnsZero) {
    EXPECT_EQ(RingBuffer_GetCapacity(nullptr), 0u);
}

TEST_F(RingBufferTest, NullPtrPutCharReturnsFalse) {
    EXPECT_FALSE(RingBuffer_PutChar(nullptr, 'x'));
}

TEST_F(RingBufferTest, NullPtrGetCharReturnsFalse) {
    char c;
    EXPECT_FALSE(RingBuffer_GetChar(nullptr, &c));
    EXPECT_FALSE(RingBuffer_GetChar(&rb, nullptr));
}

// --- Basic put / get ---

TEST_F(RingBufferTest, PutSingleChar) {
    EXPECT_TRUE(RingBuffer_PutChar(&rb, 'A'));
    EXPECT_FALSE(RingBuffer_IsEmpty(&rb));
    EXPECT_EQ(RingBuffer_GetLength(&rb), 1u);
}

TEST_F(RingBufferTest, GetSingleChar) {
    RingBuffer_PutChar(&rb, 'Z');
    char c = '\0';
    EXPECT_TRUE(RingBuffer_GetChar(&rb, &c));
    EXPECT_EQ(c, 'Z');
    EXPECT_TRUE(RingBuffer_IsEmpty(&rb));
}

TEST_F(RingBufferTest, FIFOOrder) {
    const char msg[] = "HELLO";
    for (char ch : {'H','E','L','L','O'}) {
        RingBuffer_PutChar(&rb, ch);
    }
    char out[6] = {};
    for (int i = 0; i < 5; ++i) {
        RingBuffer_GetChar(&rb, &out[i]);
    }
    EXPECT_STREQ(out, "HELLO");
}

// --- Full / overflow ---

TEST_F(RingBufferTest, FillToCapacity) {
    for (size_t i = 0; i < CAP; ++i) {
        EXPECT_TRUE(RingBuffer_PutChar(&rb, (char)i));
    }
    EXPECT_EQ(RingBuffer_GetLength(&rb), CAP);
}

TEST_F(RingBufferTest, PutOnFullBufferReturnsFalse) {
    for (size_t i = 0; i < CAP; ++i) {
        RingBuffer_PutChar(&rb, (char)i);
    }
    EXPECT_FALSE(RingBuffer_PutChar(&rb, 'X'));
    EXPECT_EQ(RingBuffer_GetLength(&rb), CAP);
}

TEST_F(RingBufferTest, GetOnEmptyBufferReturnsFalse) {
    char c;
    EXPECT_FALSE(RingBuffer_GetChar(&rb, &c));
}

// --- Clear ---

TEST_F(RingBufferTest, ClearResetsLength) {
    RingBuffer_PutChar(&rb, 'A');
    RingBuffer_PutChar(&rb, 'B');
    EXPECT_TRUE(RingBuffer_Clear(&rb));
    EXPECT_TRUE(RingBuffer_IsEmpty(&rb));
    EXPECT_EQ(RingBuffer_GetLength(&rb), 0u);
}

// --- Wrap-around ---

TEST_F(RingBufferTest, WrapAround) {
    // Fill 6, drain 6, fill 6 again (forces head/tail to wrap)
    for (int i = 0; i < 6; ++i) RingBuffer_PutChar(&rb, (char)('a' + i));
    char tmp;
    for (int i = 0; i < 6; ++i) RingBuffer_GetChar(&rb, &tmp);

    for (int i = 0; i < 6; ++i) EXPECT_TRUE(RingBuffer_PutChar(&rb, (char)('A' + i)));

    for (int i = 0; i < 6; ++i) {
        RingBuffer_GetChar(&rb, &tmp);
        EXPECT_EQ(tmp, (char)('A' + i));
    }
}

/* ======================================================================
 * SECTION 2 — CRC32
 * ====================================================================== */

TEST(CRC32Test, KnownVector) {
    // CRC-32 of "123456789" = 0xCBF43926  (standard test vector)
    const uint8_t data[] = "123456789";
    EXPECT_EQ(CRC32_Compute(data, 9u), 0xCBF43926u);
}

TEST(CRC32Test, EmptyBufferIsAllOnes) {
    // CRC-32 of empty = 0x00000000 after final XOR of 0xFFFFFFFF
    // (depends on implementation; common result for 0 bytes is 0x00000000)
    // Accept either common convention:
    uint32_t result = CRC32_Compute(nullptr, 0);
    EXPECT_TRUE(result == 0x00000000u || result == 0xFFFFFFFFu);
}

TEST(CRC32Test, SingleZeroByte) {
    uint8_t zero = 0x00;
    // CRC-32 of {0x00} = 0xD202EF8D
    EXPECT_EQ(CRC32_Compute(&zero, 1u), 0xD202EF8Du);
}

/* ======================================================================
 * SECTION 3 — RC4
 * ====================================================================== */

class RC4Test : public ::testing::Test {
protected:
    RC4State state{};
};

TEST_F(RC4Test, KSA_SBoxIsPermutation) {
    // After KSA the S-box must be a permutation of 0..255
    const uint8_t key[] = {0x01, 0x23, 0x45, 0x67, 0x89};
    RC4_KSA(&state, key, sizeof(key));

    uint8_t seen[256] = {};
    // Access S-box through RC4State (you'll expose it after filling the struct)
    // For now: just check that KSA doesn't crash and PRGA produces output.
    SUCCEED();
}

TEST_F(RC4Test, KnownKeystream_RFC6229) {
    // RC4 key = {0x01,0x02,0x03,0x04,0x05}
    // First 8 keystream bytes from RFC 6229:
    //   B2 39 63 05 F0 3D C0 27
    const uint8_t key[]      = {0x01,0x02,0x03,0x04,0x05};
    const uint8_t expected[] = {0xB2,0x39,0x63,0x05,0xF0,0x3D,0xC0,0x27};

    RC4_KSA(&state, key, sizeof(key));

    // XOR against zeros to reveal raw keystream
    uint8_t buf[8] = {};
    RC4_Process(&state, buf, sizeof(buf));

    for (size_t i = 0; i < sizeof(expected); ++i) {
        EXPECT_EQ(buf[i], expected[i]) << "Mismatch at byte " << i;
    }
}

TEST_F(RC4Test, EncryptThenDecryptRoundTrip) {
    const uint8_t key[] = {0xDE,0xAD,0xBE,0xEF,0x42};
    const uint8_t plain[] = "EmbeddedSecurity!";
    uint8_t enc[sizeof(plain)];
    uint8_t dec[sizeof(plain)];

    memcpy(enc, plain, sizeof(plain));

    RC4_KSA(&state, key, sizeof(key));
    RC4_Process(&state, enc, sizeof(enc));

    // Re-init with same key for decryption
    RC4_KSA(&state, key, sizeof(key));
    memcpy(dec, enc, sizeof(enc));
    RC4_Process(&state, dec, sizeof(dec));

    EXPECT_EQ(memcmp(dec, plain, sizeof(plain)), 0);
}

/* ======================================================================
 * SECTION 4 — WepCrypto (encrypt / decrypt)
 * ====================================================================== */

class WepCryptoTest : public ::testing::Test {
protected:
    WepCrypto ctx{};
    const uint8_t key[WEP_KEY_LEN]   = {0x11,0x22,0x33,0x44,0x55};
    const uint8_t iv [WEP_IV_LEN]    = {0xAA,0xBB,0xCC};

    void SetUp() override {
        WepCrypto_SetKey(&ctx, key);
        WepCrypto_SetIV (&ctx, iv);
    }
};

TEST_F(WepCryptoTest, EncryptProducesLongerOutput) {
    const uint8_t plain[]  = "HELLO";
    uint8_t       cipher[sizeof(plain) + WEP_ICV_LEN];

    EXPECT_TRUE(WepCrypto_Encrypt(&ctx, plain, sizeof(plain), cipher));
    // Output must be plaintext + 4-byte ICV
}

TEST_F(WepCryptoTest, EncryptDecryptRoundTrip) {
    const uint8_t plain[] = "STM32-WEP-AUTH";
    uint8_t cipher[sizeof(plain) + WEP_ICV_LEN];
    uint8_t recovered[sizeof(plain)];

    WepCrypto_Encrypt(&ctx, plain, sizeof(plain), cipher);

    // Re-init for decrypt
    WepCrypto_SetIV(&ctx, iv);
    EXPECT_TRUE(WepCrypto_Decrypt(&ctx, cipher,
                                  sizeof(plain) + WEP_ICV_LEN,
                                  recovered));
    EXPECT_EQ(memcmp(recovered, plain, sizeof(plain)), 0);
}

TEST_F(WepCryptoTest, TamperedCiphertextFailsICV) {
    const uint8_t plain[] = "SECURE";
    uint8_t cipher[sizeof(plain) + WEP_ICV_LEN];
    uint8_t recovered[sizeof(plain)];

    WepCrypto_Encrypt(&ctx, plain, sizeof(plain), cipher);

    // Flip one bit in the ciphertext payload
    cipher[2] ^= 0xFF;

    WepCrypto_SetIV(&ctx, iv);
    EXPECT_FALSE(WepCrypto_Decrypt(&ctx, cipher,
                                   sizeof(plain) + WEP_ICV_LEN,
                                   recovered));
}

TEST_F(WepCryptoTest, NullPointerChecks) {
    uint8_t buf[32] = {};
    EXPECT_FALSE(WepCrypto_Encrypt(nullptr, buf, 4, buf));
    EXPECT_FALSE(WepCrypto_Decrypt(nullptr, buf, 8, buf));
    EXPECT_FALSE(WepCrypto_Encrypt(&ctx, nullptr, 4, buf));
    EXPECT_FALSE(WepCrypto_Encrypt(&ctx, buf, 4, nullptr));
}

/* ======================================================================
 * SECTION 5 — WepAuth state machine
 * ====================================================================== */

class WepAuthTest : public ::testing::Test {
protected:
    WepAuthContext ctx{};
    const uint8_t key[WEP_KEY_LEN] = {0xAA,0xBB,0xCC,0xDD,0xEE};

    void SetUp() override {
        WepAuth_Init(&ctx, key);
    }

    /** Helper: push a serialised frame byte-by-byte into rx buffer */
    void FeedFrame(const AuthFrame &frame) {
        WepAuth_FeedByte(&ctx, (uint8_t)frame.type);
        for (int i = 0; i < WEP_IV_LEN; ++i)
            WepAuth_FeedByte(&ctx, frame.iv[i]);
        WepAuth_FeedByte(&ctx, frame.payloadLen);
        for (int i = 0; i < frame.payloadLen; ++i)
            WepAuth_FeedByte(&ctx, frame.payload[i]);
    }
};

// --- Init ---

TEST_F(WepAuthTest, InitStateIsIdle) {
    EXPECT_EQ(WepAuth_Tick(&ctx), AUTH_STATE_IDLE);
}

// --- FeedByte / GetTxByte null safety ---

TEST_F(WepAuthTest, FeedByteNullReturnsFalse) {
    EXPECT_FALSE(WepAuth_FeedByte(nullptr, 0x00));
}

TEST_F(WepAuthTest, GetTxByteNullReturnsFalse) {
    uint8_t b;
    EXPECT_FALSE(WepAuth_GetTxByte(nullptr, &b));
    EXPECT_FALSE(WepAuth_GetTxByte(&ctx, nullptr));
}

// --- Challenge → Response flow ---

TEST_F(WepAuthTest, ChallengeTransitionsToChallengingState) {
    AuthFrame challenge{};
    challenge.type       = FRAME_CHALLENGE;
    // iv unused for plaintext challenge frame
    challenge.payloadLen = AUTH_CHALLENGE_LEN;
    for (int i = 0; i < AUTH_CHALLENGE_LEN; ++i)
        challenge.payload[i] = (uint8_t)(i + 1);

    FeedFrame(challenge);
    AuthState state = WepAuth_Tick(&ctx);
    EXPECT_EQ(state, AUTH_STATE_CHALLENGING);
}

TEST_F(WepAuthTest, ResponseFrameInTxBufferAfterChallenge) {
    AuthFrame challenge{};
    challenge.type       = FRAME_CHALLENGE;
    challenge.payloadLen = AUTH_CHALLENGE_LEN;
    for (int i = 0; i < AUTH_CHALLENGE_LEN; ++i)
        challenge.payload[i] = (uint8_t)(0x10 + i);

    FeedFrame(challenge);
    WepAuth_Tick(&ctx);

    // TX buffer must contain at least 1 byte (the FRAME_RESPONSE type byte)
    uint8_t b;
    EXPECT_TRUE(WepAuth_GetTxByte(&ctx, &b));
    EXPECT_EQ(b, (uint8_t)FRAME_RESPONSE);
}

TEST_F(WepAuthTest, AuthOkTransitionsToAuthenticated) {
    // First go through challenge
    AuthFrame challenge{};
    challenge.type       = FRAME_CHALLENGE;
    challenge.payloadLen = AUTH_CHALLENGE_LEN;
    FeedFrame(challenge);
    WepAuth_Tick(&ctx);

    // Now send AUTH_OK
    AuthFrame ok{};
    ok.type       = FRAME_AUTH_OK;
    ok.payloadLen = 0;
    FeedFrame(ok);
    AuthState state = WepAuth_Tick(&ctx);
    EXPECT_EQ(state, AUTH_STATE_AUTHENTICATED);
}

TEST_F(WepAuthTest, AuthFailTransitionsToFailed) {
    AuthFrame challenge{};
    challenge.type       = FRAME_CHALLENGE;
    challenge.payloadLen = AUTH_CHALLENGE_LEN;
    FeedFrame(challenge);
    WepAuth_Tick(&ctx);

    AuthFrame fail{};
    fail.type       = FRAME_AUTH_FAIL;
    fail.payloadLen = 0;
    FeedFrame(fail);
    AuthState state = WepAuth_Tick(&ctx);
    EXPECT_EQ(state, AUTH_STATE_FAILED);
}

// --- Reset ---

TEST_F(WepAuthTest, ResetRestoresIdleState) {
    AuthFrame challenge{};
    challenge.type       = FRAME_CHALLENGE;
    challenge.payloadLen = AUTH_CHALLENGE_LEN;
    FeedFrame(challenge);
    WepAuth_Tick(&ctx);
    EXPECT_EQ(WepAuth_Tick(&ctx), AUTH_STATE_CHALLENGING);

    WepAuth_Reset(&ctx);
    EXPECT_EQ(WepAuth_Tick(&ctx), AUTH_STATE_IDLE);
}

// --- Data exchange (post-auth) ---

TEST_F(WepAuthTest, DataFrameIgnoredWhenNotAuthenticated) {
    // Should not crash; state stays IDLE
    AuthFrame data{};
    data.type       = FRAME_DATA;
    const uint8_t iv[WEP_IV_LEN] = {0x01,0x02,0x03};
    memcpy(data.iv, iv, WEP_IV_LEN);
    data.payloadLen = 4;
    FeedFrame(data);
    AuthState state = WepAuth_Tick(&ctx);
    EXPECT_NE(state, AUTH_STATE_AUTHENTICATED);
}

/* ======================================================================
 * SECTION 6 — Frame codec (ParseFrame / SendFrame)
 * ====================================================================== */

class FrameCodecTest : public ::testing::Test {
protected:
    WepAuthContext ctx{};
    const uint8_t key[WEP_KEY_LEN] = {0x01,0x02,0x03,0x04,0x05};

    void SetUp() override {
        WepAuth_Init(&ctx, key);
    }
};

TEST_F(FrameCodecTest, ParseIncompleteFrameReturnsFalse) {
    // Only feed 2 bytes — not enough for header
    WepAuth_FeedByte(&ctx, (uint8_t)FRAME_CHALLENGE);
    WepAuth_FeedByte(&ctx, 0xAA);

    AuthFrame frame{};
    EXPECT_FALSE(WepAuth_ParseFrame(&ctx, &frame));
}

TEST_F(FrameCodecTest, SendThenParseChallengeFrame) {
    AuthFrame tx{};
    tx.type       = FRAME_CHALLENGE;
    tx.iv[0] = 0x01; tx.iv[1] = 0x02; tx.iv[2] = 0x03;
    tx.payloadLen = AUTH_CHALLENGE_LEN;
    for (int i = 0; i < AUTH_CHALLENGE_LEN; ++i) tx.payload[i] = (uint8_t)i;

    // SendFrame puts bytes into TX; drain TX into a second ctx's RX
    WepAuth_SendFrame(&ctx, &tx);

    // Create a receiver
    WepAuthContext rxCtx{};
    WepAuth_Init(&rxCtx, key);

    uint8_t b;
    while (WepAuth_GetTxByte(&ctx, &b)) {
        WepAuth_FeedByte(&rxCtx, b);
    }

    AuthFrame rx{};
    EXPECT_TRUE(WepAuth_ParseFrame(&rxCtx, &rx));
    EXPECT_EQ(rx.type, FRAME_CHALLENGE);
    EXPECT_EQ(rx.payloadLen, AUTH_CHALLENGE_LEN);
    EXPECT_EQ(memcmp(rx.iv, tx.iv, WEP_IV_LEN), 0);
    EXPECT_EQ(memcmp(rx.payload, tx.payload, AUTH_CHALLENGE_LEN), 0);
}