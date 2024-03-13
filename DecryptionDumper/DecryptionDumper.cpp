#include "Driver.h"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <limits>
#include <tlhelp32.h>
#include <vector>
#include <Windows.h>

SOCKET Socket1;
SOCKET Socket2;
SOCKET Socket3;
UINT32 ProcessId = 0;
UINT64 BaseAddress = 0;
UINT64 PebAddress = 0;

bool IsProcessRunningStealth(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false; // Error handling or stealth abort
    }

    PROCESSENTRY32W pe32; // Note the 'W' at the end for Unicode
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) { // Note the 'W' for Unicode version
        CloseHandle(hSnapshot);
        return false; // Error handling or stealth abort
    }

    do {
        if (wcscmp(pe32.szExeFile, processName) == 0) { // Using wcscmp for wide char comparison
            CloseHandle(hSnapshot);
            return true; // Found the process
        }
    } while (Process32NextW(hSnapshot, &pe32)); // Note the 'W' for Unicode version

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
        ProcessId = UINT32(Driver::GetProcessId(Socket1, processName));
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
    BaseAddress = Driver::GetBaseAddress(Socket1, ProcessId);
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
    PebAddress = Driver::GetPEBAddress(Socket1, ProcessId);
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
    std::string title = make_string("Decryptor");
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

    while (true) {
        std::string input;
        std::cout << make_string("Press Enter to dump or 'q' to quit: ");
        std::getline(std::cin, input);

        if (!input.empty() && input[0] == 'q') {
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
        std::cout << make_string("Base address found, Address: ") << std::hex << BaseAddress << std::dec << std::endl;
        Sleep(1000);

        if (!UpdateProcessEnvironmentBlockAddress())
        {
            std::cout << make_string("Failed to find the PEB address") << std::endl;
            Sleep(4000);
            continue;
        }
        std::cout << make_string("PEB address found at: ") << std::hex << PebAddress << std::dec << std::endl;
        Sleep(1000);

        IMAGE_DOS_HEADER dosHeader = Driver::Read<IMAGE_DOS_HEADER>(Socket1, ProcessId, BaseAddress);

        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        {
			std::cout << make_string("Invalid DOS header") << std::endl;
			Sleep(4000);
            continue;
		}

        IMAGE_NT_HEADERS64 ntHeaders = Driver::Read<IMAGE_NT_HEADERS64>(Socket1, ProcessId, BaseAddress + dosHeader.e_lfanew);

        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
        {
            std::cout << make_string("Invalid NT header") << std::endl;
            Sleep(4000);
            continue;
        }

        std::cout << make_string("Fetched DOS and NT headers, size of image: ") << ntHeaders.OptionalHeader.SizeOfImage << make_string(" bytes");
        std::cout << make_string("  = ") << std::dec << ntHeaders.OptionalHeader.SizeOfImage / static_cast<float>(1024) << make_string(" KB");
        std::cout << make_string("  = ") << std::dec << ntHeaders.OptionalHeader.SizeOfImage / static_cast<float>(1024 * 1024) << make_string(" MB");
        std::cout << make_string("  = ") << std::dec << ntHeaders.OptionalHeader.SizeOfImage / static_cast<float>(1024 * 1024 * 1024) << make_string(" GB") << std::endl;
        Sleep(1000);

        std::vector<char> buffer(ntHeaders.OptionalHeader.SizeOfImage);
        if (!Driver::ReadMemory(Socket1, ProcessId, BaseAddress, reinterpret_cast<UINT_PTR>(buffer.data()), ntHeaders.OptionalHeader.SizeOfImage))
        {
			std::cout << make_string("Failed to read memory") << std::endl;
			Sleep(4000);
			continue;
		}

        PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
			std::cout << make_string("Invalid PIMAGE_DOS_HEADER") << std::endl;
			Sleep(4000);
            continue;
		}

        PIMAGE_NT_HEADERS64 pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(buffer.data() + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            std::cout << make_string("Invalid PIMAGE_NT_HEADERS64") << std::endl;
            Sleep(4000);
            continue;
        }

        std::cout << make_string("Read PIMAGE_DOS_HEADER and PIMAGE_NT_HEADERS64 successfully") << std::endl;
        Sleep(1000);

        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
        {
			std::cout << make_string("Section ") << i << make_string(" Name: ") << pSectionHeader->Name << make_string("  Virtual Address: ") << std::hex << pSectionHeader->VirtualAddress << std::dec << make_string("  Size: ") << pSectionHeader->Misc.VirtualSize << make_string("  Raw Size: ") << pSectionHeader->SizeOfRawData << std::endl;
			pSectionHeader++;
		}

        // Create and write the dump file
        std::string outputPath = make_string("decrypted.bin");

        std::ofstream outputFile(outputPath, std::ios::out | std::ios::binary);
        if (!outputFile.is_open()) {
            std::cerr << make_string("Failed to open output file: ") << outputPath << std::endl;
            continue;
        }

        std::clog << make_string("Starting memory dump of process ") << ProcessId << make_string(" to ") << outputPath << std::endl;

        outputFile.write(buffer.data(), ntHeaders.OptionalHeader.SizeOfImage);

        std::clog << make_string("Memory dump completed successfully.") << std::endl;
        outputFile.close();
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