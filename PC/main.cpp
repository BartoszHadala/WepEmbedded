#include "pc_config.h"
#include "serial_port.h"
#include "pc_auth.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

int main(int argc, char *argv[])
{
    const char *portName = PC_DEFAULT_PORT_NAME;

    if (argc > 1) {
        portName = argv[1];
    }

    printf("WEP SECURITY PC\n");
    printf("Otwieranie portu: %s\n", portName);

    SerialPort port;

    if (!SerialPort_Open(&port, portName, PC_DEFAULT_BAUDRATE)) {
        printf("Blad: nie udalo sie otworzyc portu %s\n", portName);
        return 1;
    }

    printf("Port otwarty poprawnie.\n");

    PcAuthContext auth;

    if (!PcAuth_Init(&auth, &port, PC_WEP_KEY)) {
        printf("Blad: nie udalo sie zainicjalizowac autoryzacji.\n");
        SerialPort_Close(&port);
        return 1;
    }

    printf("Start autoryzacji...\n");

    if (!PcAuth_Authenticate(&auth)) {
        printf("Autoryzacja NIEUDANA.\n");
        SerialPort_Close(&port);
        return 1;
    }

    printf("Autoryzacja UDANA.\n");

    const char *message = PC_TEST_MESSAGE;
    size_t messageLen = strlen(message);

    if (messageLen > 255) {
        printf("Blad: wiadomosc jest za dluga.\n");
        SerialPort_Close(&port);
        return 1;
    }

    printf("Wysylanie danych: %s\n", message);

    if (!PcAuth_SendData(&auth,
                         (const uint8_t *)message,
                         (uint8_t)messageLen)) {
        printf("Blad: nie udalo sie wyslac danych.\n");
        SerialPort_Close(&port);
        return 1;
    }

    printf("Dane wyslane poprawnie.\n");

    uint8_t receivedData[PC_AUTH_MAX_DATA_LEN];
    size_t receivedLen = 0;

    printf("Proba odebrania danych od embedded...\n");

    if (PcAuth_ReceiveData(&auth,
                           receivedData,
                           sizeof(receivedData),
                           &receivedLen,
                           PC_READ_TIMEOUT_MS)) {
        printf("Odebrano dane: ");

        for (size_t i = 0; i < receivedLen; i++) {
            printf("%c", receivedData[i]);
        }

        printf("\n");
    } else {
        printf("Brak danych od embedded albo timeout.\n");
    }

    SerialPort_Close(&port);

    printf("Port zamkniety. Koniec programu.\n");

    return 0;
}