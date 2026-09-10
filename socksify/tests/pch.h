#ifndef PCH_H
#define PCH_H

// Minimal stand-in for socksify precompiled headers in native policy tests.
#define NOMINMAX 1
#include <WinSock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#endif  // PCH_H
