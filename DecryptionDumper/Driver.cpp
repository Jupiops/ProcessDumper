#include "Driver.h"

static BOOLEAN SendPacket(const SOCKET ConnectSocket, const Packet& packet, UINT64& response)
{
    if (send(ConnectSocket, (const char*)&packet, sizeof(packet), 0) == SOCKET_ERROR)
    {
        return FALSE;
    }

    char recvbuf[sizeof(Packet)]; // Buffer large enough to hold the incoming packet
    int iResult;
    int recvbuflen = sizeof(Packet); // The expected length of the packet

    iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
    if (iResult != sizeof(Packet))
    {
        return FALSE;
    }

    // Assuming you've received the packet fully and correctly
    auto receivedPacket = reinterpret_cast<Packet*>(recvbuf);

    // Check packet type
    if (receivedPacket->header.type == PacketType::packet_completed)
    {
        response = receivedPacket->data.completed.result;
        return TRUE;
    }
    return FALSE;
}

static UINT64 CopyMem(
    const SOCKET ConnectSocket,
    const UINT32 source_process_id,
    const UINT_PTR source_address,
    const UINT32 destination_process_id,
    const UINT_PTR destination_address,
    const SIZE_T size)
{
    Packet packet;
    packet.header.type = PacketType::packet_copy_memory;
    packet.data.copy_memory.source_process_id = source_process_id;
    packet.data.copy_memory.source_address = source_address;
    packet.data.copy_memory.destination_process_id = destination_process_id;
    packet.data.copy_memory.destination_address = destination_address;
    packet.data.copy_memory.size = size;

    UINT64 response;
    if (!SendPacket(ConnectSocket, packet, response))
    {
        response = 0;
    }
    RtlSecureZeroMemory(&packet, sizeof(packet));

    return response;
}

namespace Driver
{
    UINT32 currentProcessId = 0;

    BOOLEAN TestConnection()
    {
        WSADATA wsaData;
        int iResult;

        // Initialize Winsock
        iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0)
        {
            return FALSE;
        }

        const SOCKET ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (ConnectSocket == INVALID_SOCKET)
        {
            WSACleanup();
            return FALSE;
        }

        SOCKADDR_IN clientService;
        clientService.sin_family = AF_INET;
        clientService.sin_addr.s_addr = htonl(server_ip); // Server IP
        clientService.sin_port = htons(server_port); // Server Port

        iResult = connect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService));
        if (iResult == SOCKET_ERROR)
        {
            closesocket(ConnectSocket);
            WSACleanup();
            return FALSE;
        }

        // Example process name to search for
        const auto enc = make_string("Notepad.exe");
        const auto processName = std::wstring(enc.begin(), enc.end());

        Packet packet;
        packet.header.type = PacketType::packet_get_pid; // Set the packet type
        packet.data.get_pid.process_name_length = processName.length();
        wcsncpy_s(packet.data.get_pid.process_name, processName.c_str(), processName.length() + 1);
        // Copy the process name into the struct

        iResult = send(ConnectSocket, (const char*)&packet, sizeof(packet), 0);
        if (iResult == SOCKET_ERROR)
        {
            closesocket(ConnectSocket);
            WSACleanup();
            return FALSE;
        }

        char recvbuf[sizeof(Packet)]; // Buffer large enough to hold the incoming packet
        int recvbuflen = sizeof(Packet); // The expected length of the packet

        iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
        if (iResult != sizeof(Packet))
        {
            closesocket(ConnectSocket);
            WSACleanup();
            return FALSE;
        }

        // Assuming you've received the packet fully and correctly
        auto receivedPacket = reinterpret_cast<Packet*>(recvbuf);

        // Check if the packet type is correct
        if (receivedPacket->header.type != PacketType::packet_completed)
        {
            closesocket(ConnectSocket);
            WSACleanup();
            return FALSE;
        }

        closesocket(ConnectSocket);
        WSACleanup();
        return TRUE;
    }

    BOOLEAN Initialize()
    {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            return FALSE;
        }
        currentProcessId = GetCurrentProcessId();
        return TRUE;
    }

    SOCKET Connect()
    {
        SOCKET ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (ConnectSocket == INVALID_SOCKET)
        {
            //WSACleanup();
            return INVALID_SOCKET;
        }

        SOCKADDR_IN clientService;
        clientService.sin_family = AF_INET;
        clientService.sin_addr.s_addr = htonl(server_ip); // Server IP
        clientService.sin_port = htons(server_port); // Server Port

        if (connect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService)) == SOCKET_ERROR)
        {
            closesocket(ConnectSocket);
            //WSACleanup();
            return INVALID_SOCKET;
        }

        return ConnectSocket;
    }

    VOID Disconnect(SOCKET ConnectSocket)
    {
        closesocket(ConnectSocket);
        //WSACleanup();
    }

    VOID Deinitialize()
    {
        WSACleanup();
    }

    UINT64 GetProcessId(SOCKET ConnectSocket, const std::wstring& processName)
    {
        Packet packet;
        packet.header.type = PacketType::packet_get_pid;
        packet.data.get_pid.process_name_length = processName.length();
        wcsncpy_s(packet.data.get_pid.process_name, processName.c_str(), processName.length() + 1);
        // Copy the process name into the struct

        UINT64 response;
        if (!SendPacket(ConnectSocket, packet, response))
        {
            response = 0;
        }
        RtlSecureZeroMemory(&packet, sizeof(packet));
        return response;
    }

    UINT64 GetBaseAddress(SOCKET ConnectSocket, UINT32 processId)
    {
        Packet packet;
        packet.header.type = PacketType::packet_get_base_address;
        packet.data.get_base_address.process_id = processId;

        UINT64 response;
        if (!SendPacket(ConnectSocket, packet, response))
        {
            response = 0;
        }
        RtlSecureZeroMemory(&packet, sizeof(packet));
        return response;
    }

    UINT64 GetPEBAddress(SOCKET ConnectSocket, UINT32 processId)
    {
        Packet packet;
        packet.header.type = PacketType::packet_get_peb;
        packet.data.get_peb.process_id = processId;

        UINT64 response;
        if (!SendPacket(ConnectSocket, packet, response))
        {
            response = 0;
        }
        RtlSecureZeroMemory(&packet, sizeof(packet));
        return response;
    }

    UINT64 ReadMemory(
        SOCKET ConnectSocket,
        UINT32 processId,
        UINT_PTR address,
        UINT_PTR buffer,
        SIZE_T size)
    {
        return CopyMem(ConnectSocket, processId, address, currentProcessId, buffer, size);
    }
} // namespace Driver