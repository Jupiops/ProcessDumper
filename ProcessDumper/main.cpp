#include "Driver.h"
#include "include/lazy_importer.hpp"

#include <algorithm> // Include for std::copy
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <tlhelp32.h>
#include <vector>
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

bool IsProcessRunningStealth(const wchar_t* processName)
{
    HANDLE hSnapshot = LI_FN(CreateToolhelp32Snapshot).safe()(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return true; // Error handling or stealth abort
    }

    PROCESSENTRY32W pe32; // Note the 'W' at the end for Unicode
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!LI_FN(Process32FirstW).safe()(hSnapshot, &pe32))
    {
        // Note the 'W' for Unicode version
        LI_FN(CloseHandle).safe()(hSnapshot);
        return true; // Error handling or stealth abort
    }

    do
    {
        if (wcscmp(pe32.szExeFile, processName) == 0)
        {
            // Using wcscmp for wide char comparison
            LI_FN(CloseHandle).safe()(hSnapshot);
            return true; // Found the process
        }
    }
    while (LI_FN(Process32NextW).safe()(hSnapshot, &pe32)); // Note the 'W' for Unicode version

    LI_FN(CloseHandle).safe()(hSnapshot);
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

int CalculateRealSectionSize(SOCKET socket, int processId, UINT_PTR sectionPointer, const IMAGE_SECTION_HEADER& sectionHeader)
{
    UINT_PTR sectionEnd = sectionPointer + sectionHeader.Misc.VirtualSize;
    int readSize = 100; // The chunk size for reading
    UINT_PTR currentPointer = sectionEnd;
    int calculatedSize = 0; // This will hold the calculated size of the real section data
    std::vector<BYTE> buffer(readSize);
    bool hasNonZero = false;

    while (currentPointer > sectionPointer)
    {
        if (currentPointer - readSize < sectionPointer)
        {
            readSize = currentPointer - sectionPointer; // Adjust readSize for the last chunk if necessary
        }

        currentPointer -= readSize;

        RESULT result = Driver::ReadMemory(socket, processId, currentPointer, reinterpret_cast<UINT_PTR>(buffer.data()), readSize);
        if (result.status == STATUS_SUCCESS || result.status == STATUS_PARTIAL_COPY)
        {
            for (int i = readSize - 1; i >= 0; --i)
            {
                if (buffer[i] != 0)
                {
                    hasNonZero = true;
                    // Calculate the size based on the location of the non-zero byte
                    calculatedSize = currentPointer - sectionPointer + i + 1;
                    break;
                }
            }

            if (hasNonZero)
            {
                break; // Exit the loop once non-zero data is found
            }
        }
        else
        {
            // Error handling for failed memory read
            std::cerr << make_string("Error reading process memory: 0x") << std::hex << result.status << std::dec << std::endl;
            return -1; // Use -1 or another appropriate error code
        }
    }

    return hasNonZero ? calculatedSize : 0; // Return the calculated size or 0 if no non-zero data was found
}

size_t ProbeForward(SOCKET socket, int processId, UINT_PTR currentAddress, size_t probeSize, UINT_PTR endAddress, std::vector<BYTE>& sectionData, UINT_PTR startAddress) {
    size_t skipped = 0;
    while (currentAddress < endAddress) {
        std::vector<BYTE> probeBuffer(probeSize);
        RESULT probeResult = Driver::ReadMemory(socket, processId, currentAddress, reinterpret_cast<UINT_PTR>(probeBuffer.data()), probeSize);
        if (probeResult.status == STATUS_SUCCESS || (probeResult.status == STATUS_PARTIAL_COPY && probeResult.value > 0)) {
            std::copy(probeBuffer.begin(), probeBuffer.begin() + probeResult.value, sectionData.begin() + (currentAddress - startAddress));
            return skipped; // Return the total skipped bytes up to the point of success
        } else if (probeResult.status != STATUS_PARTIAL_COPY) {
            std::cerr << make_string("Error reading memory at address 0x") << std::hex << currentAddress << make_string(" with status code: 0x") << probeResult.status << std::dec << std::endl;
            return skipped; // Return the total skipped bytes if the read failed
        }
        currentAddress += probeSize; // Increment address by probe size and continue
        skipped += probeSize; // Accumulate the total skipped bytes
    }
    return skipped; // Return the total skipped bytes if no readable segments were found
}

void ReadSectionInChunks(SOCKET socket, int processId, UINT_PTR baseAddress, const IMAGE_SECTION_HEADER& sectionHeader, std::vector<BYTE>& sectionData, std::string& sectionName) {
    UINT_PTR startAddress = baseAddress + sectionHeader.VirtualAddress;
    UINT_PTR endAddress = startAddress + sectionHeader.Misc.VirtualSize;
    UINT_PTR currentAddress = startAddress;
    const size_t CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB chunks
    const size_t PROBE_SIZE = 64 * 1024;      // Smaller probe size for detailed scanning
    size_t totalRead = 0;
    size_t totalSkipped = 0;

    sectionData.resize(sectionHeader.Misc.VirtualSize);

    while (currentAddress < endAddress) {
        size_t chunkSize = (std::min)(CHUNK_SIZE, endAddress - currentAddress);
        std::vector<BYTE> buffer(chunkSize);

        RESULT result = Driver::ReadMemory(socket, processId, currentAddress, reinterpret_cast<UINT_PTR>(buffer.data()), chunkSize);

        if (result.status == STATUS_SUCCESS) {
            std::copy(buffer.begin(), buffer.end(), sectionData.begin() + (currentAddress - startAddress));
            currentAddress += chunkSize;
            totalRead += chunkSize;
        } else if (result.status == STATUS_PARTIAL_COPY) {
            if (result.value > 0) {
                std::copy(buffer.begin(), buffer.begin() + result.value, sectionData.begin() + (currentAddress - startAddress));
                currentAddress += result.value;
                totalRead += result.value;
            } else {
                size_t skipped = ProbeForward(socket, processId, currentAddress, PROBE_SIZE, endAddress, sectionData, startAddress);
                totalSkipped += skipped;
                currentAddress += skipped; // Advance the currentAddress by the amount actually skipped
            }
        } else {
            std::cerr << make_string("Error reading memory at address 0x") << std::hex << currentAddress << make_string(" with status code: 0x") << result.status << std::dec << std::endl;
            totalSkipped += chunkSize;
            currentAddress += chunkSize; // Skip the entire chunk if completely unreadable
        }
        Sleep(10);
    }

    std::cout << make_string("Read ") << totalRead << make_string(" bytes and skipped ") << totalSkipped << make_string(" bytes for section ") << sectionName << std::endl;
}

void ReadImageInChunks(SOCKET socket, int processId, UINT_PTR baseAddress, UINT_PTR imageSize, std::vector<BYTE>& imageData) {
    UINT_PTR currentAddress = baseAddress;
    const size_t CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB chunks
    const size_t PROBE_SIZE = 64 * 1024;      // Smaller probe size for detailed scanning
    size_t totalRead = 0;
    size_t totalSkipped = 0;

    imageData.resize(imageSize);

    while (currentAddress < baseAddress + imageSize) {
        size_t chunkSize = (std::min)(CHUNK_SIZE, baseAddress + imageSize - currentAddress);
        std::vector<BYTE> buffer(chunkSize);

        RESULT result = Driver::ReadMemory(socket, processId, currentAddress, reinterpret_cast<UINT_PTR>(buffer.data()), chunkSize);

        if (result.status == STATUS_SUCCESS) {
            std::copy(buffer.begin(), buffer.end(), imageData.begin() + (currentAddress - baseAddress));
            currentAddress += chunkSize;
            totalRead += chunkSize;
        } else if (result.status == STATUS_PARTIAL_COPY) {
            if (result.value > 0) {
                std::copy(buffer.begin(), buffer.begin() + result.value, imageData.begin() + (currentAddress - baseAddress));
                currentAddress += result.value;
                totalRead += result.value;
            } else {
                size_t skipped = ProbeForward(socket, processId, currentAddress, PROBE_SIZE, baseAddress + imageSize, imageData, baseAddress);
                totalSkipped += skipped;
                currentAddress += skipped; // Advance the currentAddress by the amount actually skipped
            }
        } else {
            std::cerr << make_string("Error reading memory at address 0x") << std::hex << currentAddress << make_string(" with status code: 0x") << result.status << std::dec << std::endl;
            break;
        }
        Sleep(10);
    }

    std::cout << make_string("Read ") << totalRead << make_string(" bytes and skipped ") << totalSkipped << make_string(" bytes for the image") << std::endl;
}

void WriteBinaryData(std::ofstream& file, const void* data, size_t size) {
    if (data && size > 0) {
        file.write(reinterpret_cast<const char*>(data), size);
        if (!file) {
            std::cerr << make_string("Failed to write data to file.") << std::endl;
        }
    }
}

void WriteMemoryDump(
    const std::map<std::string, std::vector<BYTE>>& sectionData,
    const std::string& filename,
    const IMAGE_DOS_HEADER& dosHeader,
    const std::vector<BYTE>& dosStubBuffer,
    const IMAGE_NT_HEADERS64& peHeader,
    const std::vector<IMAGE_SECTION_HEADER>& sectionHeaders)
{
    std::ofstream dumpFile(filename, std::ios::out | std::ios::binary);
    if (!dumpFile.is_open()) {
        std::cerr << make_string("Failed to open file for writing: ") << filename << std::endl;
        return;
    }

    // Write the DOS header
    WriteBinaryData(dumpFile, &dosHeader, sizeof(dosHeader));

    // Write the DOS stub (if it exists)
    WriteBinaryData(dumpFile, dosStubBuffer.data(), dosStubBuffer.size());

    // Write the PE header
    WriteBinaryData(dumpFile, &peHeader, sizeof(peHeader));

    // Write all section headers
    for (const auto& header : sectionHeaders) {
        WriteBinaryData(dumpFile, &header, sizeof(IMAGE_SECTION_HEADER));
    }

    // Write each section's data
    for (const auto& section : sectionData) {
        const std::vector<BYTE>& data = section.second;
        WriteBinaryData(dumpFile, data.data(), data.size());
    }

    dumpFile.close();
    std::cout << make_string("Memory dump with headers has been written to ") << filename << std::endl;
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
    auto title = make_string("ProcDump");
    std::wstring wtitle(title.begin(), title.end());
    RtlSecureZeroMemory(&title[0], title.size());
    SetWindowText(GetConsoleWindow(), wtitle.c_str());
    SetConsoleOutputCP(CP_UTF8);

    std::cout << make_string("Starting Process Memory Dumper Build ") << make_string(__DATE__) << make_string(" ") << make_string(__TIME__) << std::endl;

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
            std::cout << make_string("Error: Invalid DOS header detected.") << std::endl;
            Sleep(4000);
            continue;
        }

        UINT_PTR peHeaderPointer = BaseAddress + dosHeader.e_lfanew;
        std::cout << make_string("Valid DOS header found. Proceeding to read the PE header at: 0x") << std::hex << peHeaderPointer << std::dec << std::endl;
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
            std::cout << make_string("Error: Invalid PE header detected.") << std::endl;
            Sleep(4000);
            continue;
        }

        std::cout << make_string("PE Header successfully retrieved. Image Size: ");
        unsigned long long imageSize = peHeader.OptionalHeader.SizeOfImage; // Store the size in bytes
        std::cout << imageSize << make_string(" bytes = ");

        // Output in KB, MB, GB with two decimal places
        std::cout << std::fixed << std::setprecision(2);
        std::cout << static_cast<double>(imageSize) / 1024 << make_string(" KB = ");
        std::cout << static_cast<double>(imageSize) / (1024 * 1024) << make_string(" MB = ");
        std::cout << static_cast<double>(imageSize) / (1024 * 1024 * 1024) << make_string(" GB") << std::endl;

        Sleep(3000);

        std::vector<BYTE> processImage(imageSize);
        ReadImageInChunks(Socket1, ProcessId, BaseAddress, imageSize, processImage);

        result = Driver::ReadMemory(Socket1, ProcessId, BaseAddress, reinterpret_cast<UINT_PTR>(processImage.data()), sizeof(IMAGE_DOS_HEADER));
        if (result.status == STATUS_SUCCESS)
        {
			std::cout << make_string("Read DOS header successfully") << std::endl;
		}
        else if (result.status == STATUS_PARTIAL_COPY)
        {
			std::cout << make_string("Partial copy with size: ") << std::dec << result.value << make_string(" bytes") << std::endl;
		}
        else
        {
			std::cout << make_string("Failed to read DOS header, status: ") << std::hex << result.status << std::dec << std::endl;
			Sleep(4000);
			continue;
		}

        PIMAGE_DOS_HEADER pNewDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(processImage.data());
        if (pNewDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			std::cout << make_string("Error: Invalid DOS header detected in the image.") << std::endl;
			Sleep(4000);
			continue;
		}

        PIMAGE_NT_HEADERS64 pNewPeHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(processImage.data() + pNewDosHeader->e_lfanew);
        if (pNewPeHeader->Signature != IMAGE_NT_SIGNATURE) {
            std::cout << make_string("Error: Invalid PE header detected in the image.") << std::endl;
            Sleep(4000);
            continue;
        }

        std::cout << make_string("Fixing section headers") << std::endl;
        PIMAGE_SECTION_HEADER pNewSectionHeader = IMAGE_FIRST_SECTION(pNewPeHeader);
        for (int i = 0; i < pNewPeHeader->FileHeader.NumberOfSections; ++i, ++pNewSectionHeader) {
			pNewSectionHeader->PointerToRawData = pNewSectionHeader->VirtualAddress;
			pNewSectionHeader->SizeOfRawData = pNewSectionHeader->Misc.VirtualSize;
		}

        const std::string filename = make_string("comp_mem_dump.exe");
        std::ofstream dumpFile(filename, std::ios::out | std::ios::binary);
        if (!dumpFile.is_open()) {
            std::cerr << make_string("Failed to open file for writing: ") << filename << std::endl;
            Sleep(4000);
            continue;
        }
        WriteBinaryData(dumpFile, processImage.data(), processImage.size());
        dumpFile.close();

        std::cout << make_string("Memory dump has been written to ") << filename << std::endl;
        
        
        /* 
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
            std::cout << make_string("Failed to read section headers. Error status: 0x") << std::hex << result.status << std::dec << std::endl;
            Sleep(4000);
            continue;
        }

        // Define a map to store section names and their corresponding data
        std::map<std::string, std::vector<BYTE>> sectionData;

        for (const auto& sectionHeader : sectionHeaders)
        {
            std::string sectionName(reinterpret_cast<const char*>(sectionHeader.Name), strnlen(reinterpret_cast<const char*>(sectionHeader.Name), sizeof(sectionHeader.Name)));
            std::cout << make_string("Processing Section: '") << sectionName << make_string("' at 0x") << std::hex << (BaseAddress + sectionHeader.VirtualAddress) << std::dec << make_string(" with Virtual Size: ") << sectionHeader.Misc.VirtualSize << make_string(" bytes.") << std::endl;

            int realSectionSize = CalculateRealSectionSize(Socket1, ProcessId, BaseAddress + sectionHeader.VirtualAddress, sectionHeader);
            if (realSectionSize == -1)
            {
                std::cout << make_string("Error: Could not calculate the real size for section '") << sectionName << make_string("'.") << std::endl;
                Sleep(4000);
                return 0;
            }
            else if (realSectionSize == 0)
            {
                std::cout << make_string("Notice: Section '") << sectionName << make_string("' is empty and will be skipped.") << std::endl;
                continue;
            }

            std::cout << make_string("Confirmed Real Size: ") << realSectionSize << make_string(" bytes for section '") << sectionName << make_string("', which is ") << (sectionHeader.Misc.VirtualSize - realSectionSize) << make_string(" bytes less than the reported virtual size.") << std::endl;

            ReadSectionInChunks(Socket1, ProcessId, BaseAddress, sectionHeader, sectionData[sectionName], sectionName);
            std::cout << std::endl;
            Sleep(50);
        }

        // Write the dump to a file
        std::string filename = make_string("comp_mem_dump.exe");
        WriteMemoryDump(sectionData, filename, dosHeader, dosStubBuffer, peHeader, sectionHeaders);

        std::cout << make_string("Memory dump has been written to ") << filename << std::endl;
        Sleep(1000);
        */

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
