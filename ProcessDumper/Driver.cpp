#include "Driver.h"

static BOOLEAN SendPacket(const SOCKET connectSocket, const Packet& packet, PRESULT response)
{
    if (send(connectSocket, (const char*)&packet, sizeof(packet), 0) == SOCKET_ERROR)
    {
        return FALSE;
    }

    char receiveBuffer[sizeof(Packet)]; // Buffer large enough to hold the incoming packet
    constexpr int receiveBufLen = sizeof(Packet); // The expected length of the packet

    int iResult = recv(connectSocket, receiveBuffer, receiveBufLen, 0);
    if (iResult != sizeof(Packet))
    {
        return FALSE;
    }

    // Assuming you've received the packet fully and correctly
    const auto receivedPacket = reinterpret_cast<Packet*>(receiveBuffer);

    // Check packet type
    if (receivedPacket->header.type == PacketType::packet_completed && receivedPacket->header.magic == packet_magic)
    {
        *response = RESULT(receivedPacket->data.completed.status, receivedPacket->data.completed.value);
        return TRUE;
    }
    return FALSE;
}

static RESULT copy_memory(
    const SOCKET connectSocket,
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

    RESULT response;
    if (!SendPacket(connectSocket, packet, &response))
    {
        response = RESULT(STATUS_UNSUCCESSFUL, 0);
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

        // Initialize Winsock
        int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0)
        {
            return FALSE;
        }

        const SOCKET connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (connectSocket == INVALID_SOCKET)
        {
            WSACleanup();
            return FALSE;
        }

        SOCKADDR_IN clientService;
        clientService.sin_family = AF_INET;
        clientService.sin_addr.s_addr = htonl(server_ip); // Server IP
        clientService.sin_port = htons(server_port); // Server Port

        iResult = connect(connectSocket, reinterpret_cast<SOCKADDR*>(&clientService), sizeof(clientService));
        if (iResult == SOCKET_ERROR)
        {
            closesocket(connectSocket);
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

        iResult = send(connectSocket, reinterpret_cast<const char*>(&packet), sizeof(packet), 0);
        if (iResult == SOCKET_ERROR)
        {
            closesocket(connectSocket);
            WSACleanup();
            return FALSE;
        }

        char receiveBuffer[sizeof(Packet)]; // Buffer large enough to hold the incoming packet
        constexpr int receiveBufLen = sizeof(Packet); // The expected length of the packet

        iResult = recv(connectSocket, receiveBuffer, receiveBufLen, 0);
        if (iResult != sizeof(Packet))
        {
            closesocket(connectSocket);
            WSACleanup();
            return FALSE;
        }

        // Assuming you've received the packet fully and correctly
        const auto receivedPacket = reinterpret_cast<Packet*>(receiveBuffer);

        // Check if the packet magic and type are correct
        if (receivedPacket->header.magic != packet_magic || receivedPacket->header.type != PacketType::packet_completed)
        {
            closesocket(connectSocket);
            WSACleanup();
            return FALSE;
        }

        closesocket(connectSocket);
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
        const SOCKET connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (connectSocket == INVALID_SOCKET)
        {
            //WSACleanup();
            return INVALID_SOCKET;
        }

        SOCKADDR_IN clientService;
        clientService.sin_family = AF_INET;
        clientService.sin_addr.s_addr = htonl(server_ip); // Server IP
        clientService.sin_port = htons(server_port); // Server Port

        if (connect(connectSocket, reinterpret_cast<SOCKADDR*>(&clientService), sizeof(clientService)) == SOCKET_ERROR)
        {
            closesocket(connectSocket);
            //WSACleanup();
            return INVALID_SOCKET;
        }

        return connectSocket;
    }

    VOID Disconnect(SOCKET connectSocket)
    {
        closesocket(connectSocket);
        //WSACleanup();
    }

    VOID Deinitialize()
    {
        WSACleanup();
    }

    RESULT GetProcessId(SOCKET connectSocket, const std::wstring& processName)
    {
        Packet packet;
        packet.header.type = PacketType::packet_get_pid;
        packet.data.get_pid.process_name_length = processName.length();
        wcsncpy_s(packet.data.get_pid.process_name, processName.c_str(), processName.length() + 1);
        // Copy the process name into the struct

        RESULT response;
        if (!SendPacket(connectSocket, packet, &response))
        {
            response = RESULT(STATUS_UNSUCCESSFUL, 0);
        }
        RtlSecureZeroMemory(&packet, sizeof(packet));
        return response;
    }

    RESULT GetBaseAddress(SOCKET connectSocket, UINT32 processId)
    {
        Packet packet;
        packet.header.type = PacketType::packet_get_base_address;
        packet.data.get_base_address.process_id = processId;

        RESULT response;
        if (!SendPacket(connectSocket, packet, &response))
        {
            response = RESULT(STATUS_UNSUCCESSFUL, 0);
        }
        RtlSecureZeroMemory(&packet, sizeof(packet));
        return response;
    }

    RESULT GetPebAddress(SOCKET connectSocket, UINT32 processId)
    {
        Packet packet;
        packet.header.type = PacketType::packet_get_peb_address;
        packet.data.get_peb.process_id = processId;

        RESULT response;
        if (!SendPacket(connectSocket, packet, &response))
        {
            response = RESULT(STATUS_UNSUCCESSFUL, 0);
        }
        RtlSecureZeroMemory(&packet, sizeof(packet));
        return response;
    }

    RESULT ReadMemory(
        SOCKET connectSocket,
        UINT32 processId,
        UINT_PTR address,
        UINT_PTR buffer,
        SIZE_T size)
    {
        return copy_memory(connectSocket, processId, address, currentProcessId, buffer, size);
    }

    RESULT GetRequiredBufferSizeForProcessList(SOCKET connectSocket)
    {
		Packet packet;
		packet.header.type = PacketType::packet_get_req_plist_buf_size;

		RESULT response;
        if (!SendPacket(connectSocket, packet, &response))
        {
			response = RESULT(STATUS_UNSUCCESSFUL, 0);
		}
		RtlSecureZeroMemory(&packet, sizeof(packet));
		return response;
	}

    RESULT GetProcessList(SOCKET connectSocket, UINT_PTR address, SIZE_T bufferSize)
    {
		Packet packet;
		packet.header.type = PacketType::packet_get_process_list;
		packet.data.get_process_list.buffer_address = address;
		packet.data.get_process_list.buffer_size = bufferSize;
		packet.data.get_process_list.process_id = currentProcessId;

		RESULT response;
        if (!SendPacket(connectSocket, packet, &response))
        {
			response = RESULT(STATUS_UNSUCCESSFUL, 0);
		}
		RtlSecureZeroMemory(&packet, sizeof(packet));
		return response;
	}
} // namespace Driver
