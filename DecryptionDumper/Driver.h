#pragma once
#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>

#include "no_strings.hpp"
#include "server_shared.h"

// Link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

typedef struct _RESULT
{
    NTSTATUS status;
    SIZE_T value;
} RESULT, *PRESULT;

namespace Driver
{
    extern UINT32 currentProcessId;

    BOOLEAN TestConnection();

    BOOLEAN Initialize();

    SOCKET Connect();

    VOID Disconnect(SOCKET connectSocket);

    VOID Deinitialize();

    RESULT GetProcessId(SOCKET connectSocket, const std::wstring& processName);

    RESULT GetBaseAddress(SOCKET connectSocket, UINT32 processId);

    RESULT GetPebAddress(SOCKET connectSocket, UINT32 processId);

    RESULT ReadMemory(SOCKET connectSocket, UINT32 processId, UINT_PTR address, UINT_PTR buffer, SIZE_T size);

    template <typename T>
    T Read(const SOCKET connectSocket, const UINT32 processId, const UINT64 address)
    {
        T result{};
        ReadMemory(connectSocket, processId, address, UINT64(&result), sizeof(T));
        return result;
    }
} // namespace Driver