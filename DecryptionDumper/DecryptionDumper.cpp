#include "Driver.h"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <limits>
#include <tlhelp32.h>
#include <vector>
#include <Windows.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000
#endif

#ifndef STATUS_PARTIAL_COPY
#define STATUS_PARTIAL_COPY ((NTSTATUS)0x8000000D)
#endif

SOCKET Socket1;
SOCKET Socket2;
SOCKET Socket3;
UINT32 ProcessId = 0;
UINT64 BaseAddress = 0;
UINT64 PebAddress = 0;

bool IsProcessRunningStealth(const wchar_t* processName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return true; // Error handling or stealth abort
    }

    PROCESSENTRY32W pe32; // Note the 'W' at the end for Unicode
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32))
    {
        // Note the 'W' for Unicode version
        CloseHandle(hSnapshot);
        return true; // Error handling or stealth abort
    }

    do
    {
        if (wcscmp(pe32.szExeFile, processName) == 0)
        {
            // Using wcscmp for wide char comparison
            CloseHandle(hSnapshot);
            return true; // Found the process
        }
    }
    while (Process32NextW(hSnapshot, &pe32)); // Note the 'W' for Unicode version

    CloseHandle(hSnapshot);
    return false; // Process not found
}

BOOLEAN WaitForAndUpdateProcessId()
{
    std::cout << make_string("Waiting for process");
    while (ProcessId == 0)
    {
        auto enc = make_string("cod.exe");
        auto processName = std::wstring(enc.begin(), enc.end());
        RtlSecureZeroMemory(&enc[0], enc.size());
        ProcessId = UINT32(Driver::GetProcessId(Socket1, processName).value);
        RtlSecureZeroMemory(&processName[0], processName.size() * sizeof(wchar_t));
        if (ProcessId == 0)
        {
            std::cout << make_string(".");
            Sleep(2000);
        }
    }
    std::cout << std::endl;
    return ProcessId != 0;
}

BOOLEAN UpdateBaseAddress()
{
    if (!Socket1 || ProcessId == 0)
    {
        return FALSE;
    }
    BaseAddress = Driver::GetBaseAddress(Socket1, ProcessId).value;
    if (BaseAddress == 0)
    {
        ProcessId = 0;
    }
    return BaseAddress != 0;
}

BOOLEAN UpdateProcessEnvironmentBlockAddress()
{
    if (!Socket1 || ProcessId == 0)
    {
        return FALSE;
    }
    PebAddress = Driver::GetPebAddress(Socket1, ProcessId).value;
    return PebAddress != 0;
}

int main()
{
    // Prevent startup if Game is already running
    auto enc = make_string("cod.exe");
    auto processName = std::wstring(enc.begin(), enc.end());
    RtlSecureZeroMemory(&enc[0], enc.size());
    if (IsProcessRunningStealth(processName.c_str()))
    {
        RtlSecureZeroMemory(&processName[0], processName.size() * sizeof(wchar_t));
        std::cout << make_string("Process already running, stop the process and try again") << std::endl;
        Sleep(4000);
        return 1;
    }
    RtlSecureZeroMemory(&processName[0], processName.size() * sizeof(wchar_t));


    // Set window title
    auto title = make_string("Decryptor");
    std::wstring wtitle(title.begin(), title.end());
    RtlSecureZeroMemory(&title[0], title.size());
    SetWindowText(GetConsoleWindow(), wtitle.c_str());
    SetConsoleOutputCP(CP_UTF8);

    std::cout << make_string("Starting Decryptor Build ") << make_string(__DATE__) << make_string(" ") << make_string(__TIME__) << std::endl;

    if (!Driver::TestConnection())
    {
        std::cout << make_string("Failed to connect to the server") << std::endl;
        Sleep(4000);
        return 1;
    }

    std::cout << make_string("Connection check successful, continuing") << std::endl;
    Sleep(500);

    if (!Driver::Initialize())
    {
        std::cout << make_string("Driver initialization failed") << std::endl;
        Sleep(4000);
        return 1;
    }

    Socket1 = Driver::Connect();
    Socket2 = Driver::Connect();
    Socket3 = Driver::Connect();

    if (Socket1 == INVALID_SOCKET || Socket2 == INVALID_SOCKET || Socket3 == INVALID_SOCKET)
    {
        std::cout << make_string("Failed to connect to the driver") << std::endl;
        if (Socket1 != INVALID_SOCKET)
        {
            Driver::Disconnect(Socket1);
        }
        if (Socket2 != INVALID_SOCKET)
        {
            Driver::Disconnect(Socket2);
        }
        if (Socket3 != INVALID_SOCKET)
        {
            Driver::Disconnect(Socket3);
        }
        Driver::Deinitialize();
        Sleep(4000);
        return 1;
    }

    if (!WaitForAndUpdateProcessId())
    {
        std::cout << make_string("Failed to find the process") << std::endl;
        Sleep(4000);
        return 1;
    }
    std::cout << make_string("Process found, PID: ") << ProcessId << std::endl;
    Sleep(1000);

    ProcessId = 0;

    while (true)
    {
        std::string input;
        std::cout << make_string("Press Enter to dump or 'q' to quit: ");
        std::getline(std::cin, input);

        if (!input.empty() && input[0] == 'q')
        {
            break; // Exit the loop if the user enters 'q'
        }

        if (!WaitForAndUpdateProcessId())
        {
            std::cout << make_string("Failed to find the process") << std::endl;
            Sleep(4000);
            continue;
        }
        std::cout << make_string("Process found, PID: ") << std::dec << ProcessId << std::endl;
        Sleep(1000);

        if (!UpdateBaseAddress())
        {
            std::cout << make_string("Failed to find the base address") << std::endl;
            Sleep(4000);
            continue;
        }
        std::cout << make_string("Base address found, Address: 0x") << std::hex << BaseAddress << std::dec << std::endl;
        Sleep(1000);

        if (!UpdateProcessEnvironmentBlockAddress())
        {
            std::cout << make_string("Failed to find the PEB address") << std::endl;
            Sleep(4000);
            continue;
        }
        std::cout << make_string("PEB address found at: 0x") << std::hex << PebAddress << std::dec << std::endl;
        Sleep(1000);

        auto dosHeader = Driver::Read<IMAGE_DOS_HEADER>(Socket1, ProcessId, BaseAddress);

        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        {
            std::cout << make_string("Invalid DOS header") << std::endl;
            Sleep(4000);
            continue;
        }

        UINT_PTR peHeaderPointer = BaseAddress + dosHeader.e_lfanew;
        std::cout << make_string("PE Header Found at: 0x") << std::hex << peHeaderPointer << std::dec << std::endl;
        UINT_PTR dosStubPointer = BaseAddress + sizeof(IMAGE_DOS_HEADER);

        std::vector<BYTE> dosStubBuffer(dosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER));
        RESULT result = Driver::ReadMemory(Socket1, ProcessId, dosStubPointer, reinterpret_cast<UINT_PTR>(dosStubBuffer.data()), dosStubBuffer.size());
        if (result.status == STATUS_SUCCESS)
        {
            std::cout << make_string("Read DOS stub successfully") << std::endl;
        }
        else if (result.status == STATUS_PARTIAL_COPY)
        {
            std::cout << make_string("Partial copy with size: ") << std::dec << result.value << make_string(" bytes") << std::endl;
        }
        else
        {
            std::cout << make_string("Failed to read DOS stub, status: ") << std::hex << result.status << std::dec << std::endl;
            Sleep(4000);
            continue;
        }
        
        auto peHeader = Driver::Read<IMAGE_NT_HEADERS64>(Socket1, ProcessId, peHeaderPointer);

        if (peHeader.Signature != IMAGE_NT_SIGNATURE)
        {
            std::cout << make_string("Invalid NT header") << std::endl;
            Sleep(4000);
            continue;
        }

        std::cout << make_string("Fetched DOS and NT headers, size of image: ") << peHeader.OptionalHeader.SizeOfImage << make_string(" bytes")
        << make_string("  = ") << std::dec << peHeader.OptionalHeader.SizeOfImage / static_cast<float>(1024) << make_string(" KB")
        << make_string("  = ") << std::dec << peHeader.OptionalHeader.SizeOfImage / static_cast<float>(1024 * 1024) << make_string(" MB")
        << make_string("  = ") << std::dec << peHeader.OptionalHeader.SizeOfImage / static_cast<float>(1024 * 1024 * 1024) << make_string(" GB") << std::endl;

        UINT_PTR sectionHeaderPointer = peHeaderPointer + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + peHeader.FileHeader.SizeOfOptionalHeader;
        std::cout << make_string("Parsing ") << std::dec << peHeader.FileHeader.NumberOfSections << make_string(" Sections at: 0x") << std::hex << sectionHeaderPointer << std::dec << std::endl;

        std::vector<IMAGE_SECTION_HEADER> sectionHeaders(peHeader.FileHeader.NumberOfSections);

        result = Driver::ReadMemory(Socket1, ProcessId, sectionHeaderPointer, reinterpret_cast<UINT_PTR>(sectionHeaders.data()), sectionHeaders.size() * sizeof(IMAGE_SECTION_HEADER));
        if (result.status == STATUS_SUCCESS)
        {
            std::cout << make_string("Read section headers successfully") << std::endl;
        }
        else if (result.status == STATUS_PARTIAL_COPY)
        {
            std::cout << make_string("Partial copy with size: ") << std::dec << result.value << make_string(" bytes") << std::endl;
        }
        else
        {
            std::cout << make_string("Failed to read section headers, status: ") << std::hex << result.status << std::dec << std::endl;
            Sleep(4000);
            continue;
        }

        for (const auto& sectionHeader : sectionHeaders)
        {
            std::string sectionName(reinterpret_cast<const char*>(sectionHeader.Name), sizeof(sectionHeader.Name));
            std::cout << make_string("Section: ") + sectionName << " (0x" << std::hex << (BaseAddress + sectionHeader.VirtualAddress) << ")," << make_string(" Size: ") << std::dec << sectionHeader.Misc.VirtualSize << " bytes" << std::endl;
        }

    }

    std::cout << make_string("Exiting") << std::endl;

    if (Socket1 != INVALID_SOCKET)
    {
        Driver::Disconnect(Socket1);
    }
    if (Socket2 != INVALID_SOCKET)
    {
        Driver::Disconnect(Socket2);
    }
    if (Socket3 != INVALID_SOCKET)
    {
        Driver::Disconnect(Socket3);
    }
    Driver::Deinitialize();
    Sleep(10000);
    return 0;
}
