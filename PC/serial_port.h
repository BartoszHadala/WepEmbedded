#ifndef SERIAL_PORT_H_
#define SERIAL_PORT_H_

/**
 * serial_port.h — PC side
 *
 * Abstrakcja portu szeregowego (UART over USB/RS232).
 * Na Windows używa WinAPI (CreateFile / ReadFile / WriteFile).
 * Na Linux używa termios (open / read / write).
 *
 * Enkapsuluje deskryptor i konfigurację (baud rate, parity, stop bits).
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define SERIAL_READ_TIMEOUT_MS  1000u  /**< Default read timeout      */
#define SERIAL_BAUD_DEFAULT     115200u

/* ------------------------------------------------------------------ */
/* Struct                                                              */
/* ------------------------------------------------------------------ */

/**
 * Represents an open serial port.
 *
 * Fields:
 *   fd          - file descriptor (int on Linux, HANDLE on Windows)
 *   isOpen      - true when the port has been successfully opened
 *   baudRate    - configured baud rate
 *   portName    - e.g. "/dev/ttyUSB0" or "COM3"
 */
typedef struct {
    intptr_t fd;
    bool     isOpen;
    uint32_t baudRate;
    char     portName[64];
} SerialPort;

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

/**
 * Opens and configures the serial port.
 *   portName  - e.g. "/dev/ttyUSB0" or "\\\\.\\COM3"
 *   baudRate  - bits per second (e.g. 115200)
 * Returns true on success.
 */
bool SerialPort_Open(SerialPort *port, const char *portName, uint32_t baudRate);

/**
 * Closes the port and marks it as not open.
 */
void SerialPort_Close(SerialPort *port);

/**
 * Writes exactly `len` bytes from `buf` to the port.
 * Returns true if all bytes were written without error.
 */
bool SerialPort_Write(SerialPort *port, const uint8_t *buf, size_t len);

/**
 * Reads exactly `len` bytes into `buf`, blocking up to SERIAL_READ_TIMEOUT_MS.
 * Returns number of bytes actually read (may be less than len on timeout).
 */
size_t SerialPort_Read(SerialPort *port, uint8_t *buf, size_t len);

/**
 * Returns true if the port is open and ready.
 */
bool SerialPort_IsOpen(const SerialPort *port);

#ifdef __cplusplus
}
#endif
#endif /* SERIAL_PORT_H_ */
