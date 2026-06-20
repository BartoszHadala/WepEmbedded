#ifndef PC_CONFIG_H
#define PC_CONFIG_H

#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Ustawienia portu szeregowego                                        */
/* ------------------------------------------------------------------ */

#define PC_DEFAULT_PORT_NAME "COM3"
#define PC_DEFAULT_BAUDRATE  115200

/* ------------------------------------------------------------------ */
/* Timeouty                                                            */
/* ------------------------------------------------------------------ */

#define PC_SERIAL_TIMEOUT_MS 3000
#define PC_AUTH_TIMEOUT_MS   3000
#define PC_READ_TIMEOUT_MS   3000

/* ------------------------------------------------------------------ */
/* Klucz WEP                                                           */
/* Musi być taki sam jak po stronie embedded                           */
/* ------------------------------------------------------------------ */

static const uint8_t PC_WEP_KEY[5] = {
    0x01, 0x02, 0x03, 0x04, 0x05
};

/* ------------------------------------------------------------------ */
/* Dane testowe                                                        */
/* ------------------------------------------------------------------ */

#define PC_TEST_MESSAGE "HELLO_FROM_PC"

#endif /* PC_CONFIG_H */