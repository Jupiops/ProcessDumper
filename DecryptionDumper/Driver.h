#pragma once
#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>

#include "no_strings.hpp"
#include "server_shared.h"

// Link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

namespace Driver {
    extern UINT32 currentProcessId;

    BOOLEAN TestConnection();

    BOOLEAN Initialize();

    SOCKET Connect();

    VOID Disconnect(SOCKET ConnectSocket);

    VOID Deinitialize();

    UINT64 GetProcessId(SOCKET ConnectSocket, const std::wstring& processName);

    UINT64 GetBaseAddress(SOCKET ConnectSocket, UINT32 pid);

    UINT64 GetPEBAddress(SOCKET ConnectSocket, UINT32 pid);

    UINT64 ReadMemory(SOCKET ConnectSocket, UINT32 pid, UINT_PTR address, UINT_PTR buffer, SIZE_T size);

    template <typename T>
    T Read(const SOCKET ConnectSocket, const UINT32 pid, const UINT64 address)
    {
        T result{ };
        ReadMemory(ConnectSocket, pid, address, UINT64(&result), sizeof(T));
        return result;
    }
} // namespace Driver