# WEP Embedded — STM32 side

## Struktura projektu

```
include/
  ring_buffer.h   ← struct + API (wypełniony)
  wep_crypto.h    ← RC4State, WepCrypto struct + API (wypełniony)
  wep_auth.h      ← AuthFrame, WepAuthContext struct + API (wypełniony)

src/
  ring_buffer.cpp ← do zaimplementowania
  wep_crypto.cpp  ← do zaimplementowania
  wep_auth.cpp    ← do zaimplementowania

tests/
  test_all.cpp    ← TDD (Google Test, nie ruszaj)
```

## Kolejność implementacji

1. `ring_buffer.cpp` — bez zależności, zacznij tu
2. `wep_crypto.cpp`  — CRC32 → RC4_KSA → RC4_PRGA → RC4_Process → SetKey/SetIV → Encrypt/Decrypt
3. `wep_auth.cpp`    — build_iv → Init/Reset → FeedByte/GetTxByte → ParseFrame/SendFrame → handlery → Tick

## Budowanie i testy (VSCode / terminal)

```bash
cmake -S . -B build
cmake --build build
cd build && ctest --output-on-failure
```

Lub bezpośrednio:
```bash
./build/run_tests
```

## Protokół (przypomnienie)

```
PC                          STM32
 |                            |
 |── FRAME_CHALLENGE ────────>|  (16 bajtów plaintext)
 |                            |  HandleChallenge: encrypt(challenge) → RC4(IV||key)
 |<─ FRAME_RESPONSE ──────────|  (IV + zaszyfrowane 16B + ICV)
 |                            |
 |  [PC weryfikuje ICV]        |
 |── FRAME_AUTH_OK ──────────>|  lub FRAME_AUTH_FAIL
 |                            |
 |<═══ szyfrowana wymiana ════>|  FRAME_DATA w obie strony
```