#include "serial_port.h"
#include <string.h>
#include <assert.h>

/* ------------------------------------------------------------------ */
/* Platform includes                                                   */
/* Odkomentuj właściwy blok zależnie od systemu.                       */
/* ------------------------------------------------------------------ */

#if defined(_WIN32) || defined(_WIN64)
  #include <windows.h>
  #define PLATFORM_WINDOWS
#else
  // #include <fcntl.h>
  // #include <unistd.h>
  // #include <termios.h>
  // #include <errno.h>
  #define PLATFORM_LINUX
#endif

/* ------------------------------------------------------------------ */

bool SerialPort_Open(SerialPort *port, const char *portName, uint32_t baudRate)
{
    if (port == NULL || portName == NULL) {
        return false;
    }

    //Czyszczenie struktury
    port->fd = 0;
    port->isOpen = false;
    port->baudRate = 0;
    port->portName[0] = '\0';

    HANDLE COM = CreateFileA(
        portName, //nazwa portu który chcemy otworzyć
        GENERIC_READ | GENERIC_WRITE, //czytanie pisanie do porut
        0, //tylko ja mogę korzystać z portu
        NULL,
        OPEN_EXISTING, //otwórz jeśli istnieje
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (COM == INVALID_HANDLE_VALUE) {
        return false;
    }

    DCB dcb = { 0 };
    dcb.DCBlength = sizeof(dcb);

    if (!GetCommState(COM, &dcb)) { //jeśli nie pobrałeś ustawień portu
        CloseHandle(COM); //zamknij port
        return false;
    }

    //ustawienie 8n1 -8 bitów danych 1 stop bit
    dcb.BaudRate = baudRate;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;

    if (!SetCommState(COM, &dcb)) {
        CloseHandle(COM); //jeśli nie udało się pobrać zamknij port
        return false;
    }

    COMMTIMEOUTS timeouts = { 0 }; //wyzerowanie struktury timeoutów
    timeouts.ReadTotalTimeoutConstant = SERIAL_READ_TIMEOUT_MS; //limit czasu na odczyt
    timeouts.WriteTotalTimeoutConstant = SERIAL_READ_TIMEOUT_MS; //limit czasu na zapis

    if (!SetCommTimeouts(COM, &timeouts)) { //zapisanie timeoutów do com
        CloseHandle(COM); 
        return false;
    }

    //zapisanie do własnej struktury
    port->fd = (intptr_t)COM;
    port->isOpen = true;
    port->baudRate = baudRate;

    strncpy(port->portName, portName, sizeof(port->portName) - 1); //nazwa portu do struktury tak żeby nie wyjsć za obaszar
    port->portName[sizeof(port->portName) - 1] = '\0'; //ręczne zapisanie znaku końca

    return true;


    // Hint (Linux):
    //   1. fd = open(portName, O_RDWR | O_NOCTTY | O_SYNC)
    //   2. Skonfiguruj termios: baud, 8N1, no flow control
    //      cfsetispeed / cfsetospeed → mapuj baudRate na B115200 itd.
    //   3. tcsetattr(fd, TCSANOW, &tty)
    //   4. port->isOpen = true, port->fd = fd
    //   5. strncpy(port->portName, ...)
    //
    // Hint (Windows):
    //   1. HANDLE h = CreateFile(portName, GENERIC_READ|GENERIC_WRITE, ...)
    //   2. GetCommState → DCB → ustaw BaudRate, ByteSize=8, Parity=NOPARITY
    //   3. SetCommState, SetCommTimeouts
    //   4. port->fd = (int)(intptr_t)h, port->isOpen = true
    // todo
   
}

void SerialPort_Close(SerialPort *port)
{
    if (port == NULL) {
        return;
    }


    if (port->isOpen && port->fd != 0) {
        HANDLE COM = (HANDLE)port->fd;
        CloseHandle(COM);
    }

    port->fd = 0;
    port->isOpen = false;
    port->baudRate = 0;
    port->portName[0] = '\0';
    // Hint (Linux):  if (port->isOpen) close(port->fd)
    // Hint (Windows): CloseHandle((HANDLE)(intptr_t)port->fd)
    // port->isOpen = false
    // todo
}

bool SerialPort_Write(SerialPort *port, const uint8_t *buf, size_t len)
{
    if (port == NULL || buf == NULL) {
        return false;
    }

    if (!port->isOpen || port->fd == 0) {
        return false;
    }

    HANDLE COM = (HANDLE)port->fd; 

    DWORD written = 0; //DWORD -windowsowy typ licznika 32 bitowy, written - wpisze tu ile bajtów wysłano

    BOOL result = WriteFile(
        COM,
        buf,
        (DWORD)len,
        &written,
        NULL
    );

    if (!result) {
        return false;
    }

    return written == len; //sprawdzenie czy wysłaliśmy tyle bajtów ile chcieliśmy
    // Hint (Linux):
    //   ssize_t written = write(port->fd, buf, len)
    //   return written == (ssize_t)len
    //
    // Hint (Windows):
    //   DWORD written; WriteFile(h, buf, len, &written, NULL)
    //   return written == len
    // todo
}

size_t SerialPort_Read(SerialPort *port, uint8_t *buf, size_t len)
{
    if (port == NULL || buf == NULL) {
        return 0;
    }

    if (!port->isOpen || port->fd == 0) {
        return 0;
    }

    HANDLE COM = (HANDLE)port->fd;

    DWORD bytesRead = 0;

    BOOL result = ReadFile(
        COM,
        buf,
        (DWORD)len,
        &bytesRead,
        NULL
    );

    if (!result) {
        return 0;
    }

    return (size_t)bytesRead;
    // Hint (Linux):
    //   ssize_t n = read(port->fd, buf, len)
    //   return (n < 0) ? 0 : (size_t)n
    //
    // Hint (Windows):
    //   DWORD n; ReadFile(h, buf, len, &n, NULL)
    //   return (size_t)n
    // todo
    return 0;
}

bool SerialPort_IsOpen(const SerialPort *port)
{
    if (port == NULL) {
        return false;
    }

    return port->isOpen && port->fd != 0;
}
