#include "Driver.h"
#include "include/lazy_importer.hpp"

#include <algorithm> // Include for std::copy
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <tlhelp32.h>
#include <vector>
#include <stdexcept>
#define _WINSOCKAPI_    // stops windows.h including winsock.h
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

bool IsProcessRunningStealth(const wchar_t* processName) {
    HANDLE hSnapshot = LI_FN(CreateToolhelp32Snapshot).safe()(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        throw std::runtime_error(make_string("Failed to create process snapshot"));
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!LI_FN(Process32FirstW).safe()(hSnapshot, &pe32)) {
        LI_FN(CloseHandle).safe()(hSnapshot);
        throw std::runtime_error(make_string("Failed to retrieve the first process in the snapshot"));
    }

    do {
        if (wcscmp(pe32.szExeFile, processName) == 0) {
            LI_FN(CloseHandle).safe()(hSnapshot);
            return true; // Found the process
        }
    }
    while (LI_FN(Process32NextW).safe()(hSnapshot, &pe32));

    LI_FN(CloseHandle).safe()(hSnapshot);
    return false; // Process not found
}

BOOLEAN WaitForAndUpdateProcessId(const std::wstring& processName) {
    std::cout << make_string("Waiting for process");
    while (ProcessId == 0) {
        ProcessId = UINT32(Driver::GetProcessId(Socket1, processName).value);
        if (ProcessId == 0) {
            std::cout << make_string(".");
            Sleep(2000);
        }
    }
    std::cout << std::endl;
    return ProcessId != 0;
}

BOOLEAN UpdateBaseAddress() {
    if (!Socket1 || ProcessId == 0) {
        return FALSE;
    }
    BaseAddress = Driver::GetBaseAddress(Socket1, ProcessId).value;
    if (BaseAddress == 0) {
        ProcessId = 0;
    }
    return BaseAddress != 0;
}

BOOLEAN UpdateProcessEnvironmentBlockAddress() {
    if (!Socket1 || ProcessId == 0) {
        return FALSE;
    }
    PebAddress = Driver::GetPebAddress(Socket1, ProcessId).value;
    return PebAddress != 0;
}

void writeMemoryDumpToFile(const std::vector<BYTE>& dataBuffer, const std::string& filePath) {
    std::ofstream outFile(filePath, std::ios::out | std::ios::binary);
    if (!outFile) {
        throw std::runtime_error(make_string("Failed to open file for writing."));
    }

    outFile.write(reinterpret_cast<const char*>(dataBuffer.data()), dataBuffer.size());

    if (outFile.bad()) {
        throw std::runtime_error(make_string("Error occurred during file write."));
    }

    std::cout << make_string("Dump successfully written to file.") << std::endl;
    outFile.close();
}

std::wstring getProcessNameFromUser() {
    std::string choice;
    std::cout << make_string("Select the process to dump:\n1. cod.exe\n2. XDefiant.exe\n3. Provide custom process name\nChoice: ");
    std::getline(std::cin, choice);

    std::string encryptedChoice;

    if (choice == make_string("1")) {
        encryptedChoice = make_string("cod.exe");
    } else if (choice == make_string("2")) {
        encryptedChoice = make_string("XDefiant.exe");
    } else if (choice == make_string("3")) {
        std::cout << make_string("Enter the name of the process (with .exe extension): ");
        std::getline(std::cin, encryptedChoice);
    } else {
        throw std::invalid_argument(make_string("Invalid choice."));
    }
    auto procName = std::wstring(encryptedChoice.begin(), encryptedChoice.end());
    RtlSecureZeroMemory(&encryptedChoice[0], encryptedChoice.size());
    return procName;
}

std::string generateOutputFilePath(const std::wstring& processName) {
    // Get current time
    std::time_t t = std::time(nullptr);
    std::tm tm;
    localtime_s(&tm, &t);

    // Format date and time
    char timeStr[100];
    std::strftime(timeStr, sizeof(timeStr), make_string("%Y%m%d_%H%M%S").c_str(), &tm);

    // Convert process name to narrow string and remove .exe extension
    std::string processNameStr(processName.begin(), processName.end());
    size_t pos = processNameStr.find(make_string(".exe"));
    if (pos != std::string::npos) {
        processNameStr.erase(pos, 4);
    }

    // Create file path
    return processNameStr + make_string("_dump_") + timeStr + make_string(".exe");
}

int main() {
    try {
        std::wstring processName = getProcessNameFromUser();

        if (IsProcessRunningStealth(processName.c_str())) {
            RtlSecureZeroMemory(&processName[0], processName.size() * sizeof(wchar_t));
            std::cerr << make_string("Process already running, stop the process and try again") << std::endl;
            Sleep(4000);
            return 1;
        }

        auto title = make_string("ProcDump");
        std::wstring wtitle(title.begin(), title.end());
        RtlSecureZeroMemory(&title[0], title.size());
        SetWindowText(GetConsoleWindow(), wtitle.c_str());
        SetConsoleOutputCP(CP_UTF8);

        std::cout << make_string("Starting Process Memory Dumper Build ") << make_string(__DATE__) << make_string(" ") << make_string(__TIME__) << std::endl;

        if (!Driver::TestConnection()) {
            throw std::runtime_error(make_string("Failed to connect to the server"));
        }

        std::cout << make_string("Connection check successful, continuing") << std::endl;
        Sleep(500);

        if (!Driver::Initialize()) {
            throw std::runtime_error(make_string("Driver initialization failed"));
        }

        Socket1 = Driver::Connect();
        Socket2 = Driver::Connect();
        Socket3 = Driver::Connect();

        if (Socket1 == INVALID_SOCKET || Socket2 == INVALID_SOCKET || Socket3 == INVALID_SOCKET) {
            throw std::runtime_error(make_string("Failed to connect to the driver"));
        }

        if (!WaitForAndUpdateProcessId(processName)) {
            throw std::runtime_error(make_string("Failed to find the process"));
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

            if (!WaitForAndUpdateProcessId(processName)) {
                std::cerr << make_string("Failed to find the process") << std::endl;
                Sleep(4000);
                continue;
            }
            std::cout << make_string("Process found, PID: ") << std::dec << ProcessId << std::endl;
            Sleep(1000);

            if (!UpdateBaseAddress()) {
                std::cerr << make_string("Failed to find the base address") << std::endl;
                Sleep(4000);
                continue;
            }
            std::cout << make_string("Base address found, Address: 0x") << std::hex << BaseAddress << std::dec << std::endl;
            Sleep(1000);

            if (!UpdateProcessEnvironmentBlockAddress()) {
                std::cerr << make_string("Failed to find the PEB address") << std::endl;
                Sleep(4000);
                continue;
            }
            std::cout << make_string("PEB address found at: 0x") << std::hex << PebAddress << std::dec << std::endl;
            Sleep(1000);

            auto dosHeader = Driver::Read<IMAGE_DOS_HEADER>(Socket1, ProcessId, BaseAddress);

            if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
                std::cerr << make_string("Error: Invalid DOS header detected.") << std::endl;
                Sleep(4000);
                continue;
            }

            UINT_PTR peHeaderPointer = BaseAddress + dosHeader.e_lfanew;
            std::cout << make_string("Valid DOS header found. Proceeding to read the PE header at: 0x") << std::hex << peHeaderPointer << std::dec << std::endl;
            UINT_PTR dosStubPointer = BaseAddress + sizeof(IMAGE_DOS_HEADER);

            std::vector<BYTE> dosStubBuffer(dosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER));
            RESULT result = Driver::ReadMemory(Socket1, ProcessId, dosStubPointer, reinterpret_cast<UINT_PTR>(dosStubBuffer.data()), dosStubBuffer.size());
            if (result.status == STATUS_SUCCESS) {
                std::cout << make_string("Read DOS stub successfully") << std::endl;
            } else if (result.status == STATUS_PARTIAL_COPY) {
                std::cout << make_string("Partial copy with size: ") << std::dec << result.value << make_string(" bytes") << std::endl;
            } else {
                std::cerr << make_string("Failed to read DOS stub, status: ") << std::hex << result.status << std::dec << std::endl;
                Sleep(4000);
                continue;
            }

            auto peHeader = Driver::Read<IMAGE_NT_HEADERS64>(Socket1, ProcessId, peHeaderPointer);

            if (peHeader.Signature != IMAGE_NT_SIGNATURE) {
                std::cerr << make_string("Error: Invalid PE header detected.") << std::endl;
                Sleep(4000);
                continue;
            }

            std::cout << make_string("PE Header successfully retrieved. Image Size: ");
            UINT_PTR imageSize = peHeader.OptionalHeader.SizeOfImage;
            std::cout << imageSize << make_string(" bytes = ");

            std::cout << std::fixed << std::setprecision(2);
            std::cout << static_cast<double>(imageSize) / 1024 << make_string(" KB = ");
            std::cout << static_cast<double>(imageSize) / (1024 * 1024) << make_string(" MB = ");
            std::cout << static_cast<double>(imageSize) / (1024 * 1024 * 1024) << make_string(" GB") << std::endl;

            UINT_PTR sectionHeaderPointer = peHeaderPointer + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + peHeader.FileHeader.SizeOfOptionalHeader;
            std::cout << make_string("Parsing ") << std::dec << peHeader.FileHeader.NumberOfSections << make_string(" Sections at: 0x") << std::hex << sectionHeaderPointer << std::dec << std::endl;

            std::vector<IMAGE_SECTION_HEADER> sectionHeaders(peHeader.FileHeader.NumberOfSections);

            result = Driver::ReadMemory(Socket1, ProcessId, sectionHeaderPointer, reinterpret_cast<UINT_PTR>(sectionHeaders.data()), sectionHeaders.size() * sizeof(IMAGE_SECTION_HEADER));
            if (result.status == STATUS_SUCCESS) {
                std::cout << make_string("Read section headers successfully") << std::endl;
            } else if (result.status == STATUS_PARTIAL_COPY) {
                std::cout << make_string("Partial copy with size: ") << std::dec << result.value << make_string(" bytes") << std::endl;
            } else {
                std::cerr << make_string("Failed to read section headers. Error status: 0x") << std::hex << result.status << std::dec << std::endl;
                Sleep(4000);
                continue;
            }

            std::vector<BYTE> fullImageBuffer(imageSize);

            Sleep(500);

            std::copy(reinterpret_cast<const char*>(&dosHeader), reinterpret_cast<const char*>(&dosHeader) + sizeof(IMAGE_DOS_HEADER), fullImageBuffer.begin());
            std::copy(dosStubBuffer.begin(), dosStubBuffer.end(), fullImageBuffer.begin() + sizeof(IMAGE_DOS_HEADER));
            std::copy(reinterpret_cast<const char*>(&peHeader), reinterpret_cast<const char*>(&peHeader) + sizeof(IMAGE_NT_HEADERS64), fullImageBuffer.begin() + dosHeader.e_lfanew);

            size_t offset = sectionHeaderPointer - BaseAddress;

            if (offset + sectionHeaders.size() * sizeof(IMAGE_SECTION_HEADER) <= fullImageBuffer.size()) {
                auto dest = reinterpret_cast<char*>(fullImageBuffer.data() + offset);
                std::copy(reinterpret_cast<const char*>(sectionHeaders.data()), reinterpret_cast<const char*>(sectionHeaders.data()) + sectionHeaders.size() * sizeof(IMAGE_SECTION_HEADER), dest);
            } else {
                throw std::runtime_error(make_string("Buffer overflow prevented while trying to copy section headers."));
            }

            constexpr size_t chunkSize = 4 * 1024 * 1024; // 4 MB per chunk
            size_t bytesRead = sizeof(IMAGE_DOS_HEADER) + dosStubBuffer.size() + sizeof(IMAGE_NT_HEADERS64);
            size_t totalSkippedBytes = 0;

            while (bytesRead < imageSize) {
                size_t toRead = (std::min)(chunkSize, imageSize - bytesRead);
                RESULT chunkResult = Driver::ReadMemory(Socket1, ProcessId, BaseAddress + bytesRead, reinterpret_cast<UINT_PTR>(fullImageBuffer.data() + bytesRead), toRead);

                if (chunkResult.status == STATUS_SUCCESS || (chunkResult.status == STATUS_PARTIAL_COPY && chunkResult.value > 0)) {
                    bytesRead += chunkResult.value;

                    if (chunkResult.status == STATUS_PARTIAL_COPY) {
                        continue;
                    }
                } else if (chunkResult.status == STATUS_PARTIAL_COPY && chunkResult.value == 0) {
                    constexpr size_t skipSize = 1024;
                    bytesRead += skipSize;
                    totalSkippedBytes += skipSize;
                } else {
                    std::cerr << make_string("Failed to read memory, status: ") << std::hex << chunkResult.status << std::dec << std::endl;
                    break;
                }
                Sleep(10);
            }

            std::cout << make_string("Total Skipped Bytes: ") << totalSkippedBytes << make_string(" bytes.") << std::endl;

            Sleep(500);

            auto pNewDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(fullImageBuffer.data());
            if (pNewDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                std::cerr << make_string("Error: Invalid DOS header detected in the image.") << std::endl;
                Sleep(4000);
                continue;
            }

            auto pNewPeHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(fullImageBuffer.data() + pNewDosHeader->e_lfanew);
            if (pNewPeHeader->Signature != IMAGE_NT_SIGNATURE) {
                std::cerr << make_string("Error: Invalid PE header detected in the image.") << std::endl;
                Sleep(4000);
                continue;
            }

            std::cout << make_string("Fixing section headers") << std::endl;
            auto pNewSectionHeader = IMAGE_FIRST_SECTION(pNewPeHeader);
            for (int i = 0; i < pNewPeHeader->FileHeader.NumberOfSections; ++i, ++pNewSectionHeader) {
                pNewSectionHeader->PointerToRawData = pNewSectionHeader->VirtualAddress;
                pNewSectionHeader->SizeOfRawData = pNewSectionHeader->Misc.VirtualSize;
            }

            std::string outputFilePath = generateOutputFilePath(processName);
            writeMemoryDumpToFile(fullImageBuffer, outputFilePath);
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    std::cout << make_string("Exiting") << std::endl;

    if (Socket1 != INVALID_SOCKET) {
        Driver::Disconnect(Socket1);
    }
    if (Socket2 != INVALID_SOCKET) {
        Driver::Disconnect(Socket2);
    }
    if (Socket3 != INVALID_SOCKET) {
        Driver::Disconnect(Socket3);
    }
    Driver::Deinitialize();
    Sleep(10000);
    return 0;
}
