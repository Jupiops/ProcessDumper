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
        return false; // Error handling or stealth abort
    }

    PROCESSENTRY32W pe32; // Note the 'W' at the end for Unicode
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32))
    {
        // Note the 'W' for Unicode version
        CloseHandle(hSnapshot);
        return false; // Error handling or stealth abort
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

        auto dosHeader = Driver::Read<IMAGE_DOS_HEADER>(Socket1, ProcessId, BaseAddress);

        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        {
            std::cout << make_string("Invalid DOS header") << std::endl;
            Sleep(4000);
            continue;
        }

        auto ntHeaders = Driver::Read<IMAGE_NT_HEADERS64>(Socket1, ProcessId, BaseAddress + dosHeader.e_lfanew);

        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
        {
            std::cout << make_string("Invalid NT header") << std::endl;
            Sleep(4000);
            continue;
        }

        std::cout << make_string("Fetched DOS and NT headers, size of image: ") << ntHeaders.OptionalHeader.SizeOfImage << make_string(" bytes")
        << make_string("  = ") << std::dec << ntHeaders.OptionalHeader.SizeOfImage / static_cast<float>(1024) << make_string(" KB")
        << make_string("  = ") << std::dec << ntHeaders.OptionalHeader.SizeOfImage / static_cast<float>(1024 * 1024) << make_string(" MB")
        << make_string("  = ") << std::dec << ntHeaders.OptionalHeader.SizeOfImage / static_cast<float>(1024 * 1024 * 1024) << make_string(" GB") << std::endl;

        SIZE_T headerSize = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

        std::cout << make_string("Header size: ") << std::dec << headerSize << make_string(" bytes") <<
            make_string("  = ") << std::dec << headerSize / static_cast<float>(1024) << make_string(" KB") <<
            make_string("  = ") << std::dec << headerSize / static_cast<float>(1024 * 1024) << make_string(" MB") <<
            std::endl;

        std::vector<UINT8> headerBuffer(headerSize);
        Sleep(1000);


        RESULT result = Driver::ReadMemory(Socket1, ProcessId, BaseAddress, reinterpret_cast<UINT_PTR>(headerBuffer.data()), headerSize);

        if (result.status == STATUS_SUCCESS)
        {
            std::cout << make_string("Read memory successfully") << std::endl;
        }
        else if (result.status == STATUS_PARTIAL_COPY)
        {
            std::cout << make_string("Partial copy with size: ") << std::dec << result.value << make_string(" bytes") << std::endl;
        }
        else
        {
            std::cout << make_string("Failed to read memory, status: ") << std::hex << result.status << std::dec << std::endl;
            Sleep(4000);
            continue;
        }

        auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(headerBuffer.data());
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            std::cout << make_string("Invalid PIMAGE_DOS_HEADER") << std::endl;
            Sleep(4000);
            continue;
        }

        auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(headerBuffer.data() + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            std::cout << make_string("Invalid PIMAGE_NT_HEADERS64") << std::endl;
            Sleep(4000);
            continue;
        }

        std::cout << make_string("Read PIMAGE_DOS_HEADER and PIMAGE_NT_HEADERS64 successfully") << std::endl;
        Sleep(1000);

        result = Driver::GetRequiredBufferSizeForProcessList(Socket1);

        if (result.status != STATUS_SUCCESS)
        {
			std::cout << make_string("Failed to get required buffer size for process list, status: ") << std::hex << result.status << std::dec << std::endl;
			Sleep(4000);
			continue;
		}

        std::cout << make_string("Required buffer size for process list: ") << std::dec << result.value << make_string(" bytes, eqivalent to ") << std::dec << result.value / sizeof(PROCESS_SUMMARY) << make_string(" processes") << std::endl;

        std::vector<UINT8> processListBuffer(result.value);

        result = Driver::GetProcessList(Socket1, reinterpret_cast<UINT_PTR>(processListBuffer.data()), result.value);

        if (result.status != STATUS_SUCCESS)
        {
			std::cout << make_string("Failed to get process list, status: ") << std::hex << result.status << std::dec << std::endl;
			Sleep(4000);
			continue;
		}

        std::cout << make_string("Got process list successfully, number of processes: ") << std::dec << result.value << std::endl;

        auto pProcessSummary = reinterpret_cast<PPROCESS_SUMMARY>(processListBuffer.data());

        for (size_t i = 0; i < result.value; i++)
        {
            std::cout << make_string("Process ID: ") << pProcessSummary[i].ProcessId << make_string(", Main Module Base: ") << std::hex << pProcessSummary[i].MainModuleBase << std::dec << make_string(", Main Module File Name: ");
            std::wcout << pProcessSummary[i].MainModuleFileName;
            std::cout << make_string(", Main Module Image Size: ") << std::dec << pProcessSummary[i].MainModuleImageSize << make_string(" bytes") << make_string(", Main Module Entry Point: ") << std::hex << pProcessSummary[i].MainModuleEntryPoint << std::dec << make_string(", WOW64: ") << (pProcessSummary[i].WOW64 ? make_string("Yes") : make_string("No")) << std::endl;
		}

        Sleep(2000);

        auto pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        std::vector<std::vector<UINT8>> sectionBuffers;

        for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++, pSectionHeader++)
        {
            // Create a buffer for the section
            std::vector<UINT8> currentSectionBuffer(pSectionHeader->Misc.VirtualSize);

            UINT_PTR sectionStart = BaseAddress + pSectionHeader->VirtualAddress;
            UINT_PTR sectionEnd = sectionStart + pSectionHeader->Misc.VirtualSize;
            UINT_PTR currentAddress = sectionStart;
            size_t totalBytesRead = 0;

            while (currentAddress < sectionEnd)
            {
                Sleep(200);
                UINT_PTR bufferOffset = currentAddress - sectionStart;
                size_t sizeToRead = sectionEnd - currentAddress;

                // Read the section into the buffer
                result = Driver::ReadMemory(Socket1, ProcessId, currentAddress, reinterpret_cast<UINT_PTR>(currentSectionBuffer.data()) + bufferOffset, sizeToRead);

                if (result.status == STATUS_SUCCESS)
                {
                    // If read was successful, adjust total bytes read and break the loop
                    totalBytesRead += sizeToRead;
                    break;
                }
                else if (result.status == STATUS_PARTIAL_COPY)
                {
                    // On partial copy, adjust the current address and total bytes read based on the amount successfully copied
                    totalBytesRead += result.value;
                    currentAddress += result.value;

                    std::cout << make_string("Partial copy encountered in section ") << pSectionHeader->Name << make_string(" at address: ") << std::hex << currentAddress << std::dec << make_string(", read size: ") << std::dec << result.value << make_string(" bytes, expected size: ") << std::dec << sizeToRead << make_string(" bytes") << std::endl;
                    
                    // Optionally, skip a small, predefined number of bytes to attempt to bypass inaccessible memory,
                    // then try reading again from this new address. Adjust this value as necessary.
                    currentAddress += 1024; // Skipping 1 kb; adjust based on your requirements.
                }
                else
                {
                    // Handle other errors (optional)
                    std::cout << make_string("Failed to read section ") << pSectionHeader->Name << make_string(", status: ") << std::hex << result.status << std::dec << make_string(", read size: ") << std::dec << result.value << make_string(" bytes, expected size: ") << std::dec << sizeToRead << make_string(" bytes") << std::endl;

                    break;
                }
            }

            // Add the current section buffer to sectionBuffers
            sectionBuffers.push_back(std::move(currentSectionBuffer));

            // Update the section header to reflect the actual size of data read
            pSectionHeader->SizeOfRawData = static_cast<DWORD>(totalBytesRead);
            pSectionHeader->PointerToRawData = static_cast<DWORD>(sectionStart - BaseAddress);
        }

        std::string dumpFilePath = make_string("dump.bin");

        std::ofstream dumpFile(dumpFilePath, std::ios::out | std::ios::binary);
        if (!dumpFile.is_open()) {
            std::cerr << make_string("Failed to open dump file.") << std::endl;
            return 1;
        }

        // Write header data
        dumpFile.write(reinterpret_cast<const char*>(headerBuffer.data()), headerBuffer.size());

        // Write section data
        for (const auto& sectionBuffer : sectionBuffers) {
            dumpFile.write(reinterpret_cast<const char*>(sectionBuffer.data()), sectionBuffer.size());
        }

        dumpFile.close();
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
