#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// DOS Header Struct
typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER;

// File Header Struct
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

//Optional Header Struct (64 bit)
typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    struct {
        uint32_t VirtualAddress;
        uint32_t Size;
    } DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

// PE Header Struct (64 bit)
typedef struct {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

//Optional Header Struct (32 bit)
typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    struct {
        uint32_t VirtualAddress;
        uint32_t Size;
    } DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32;

// PE Header Struct (32 bit)
typedef struct {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;

// Section Table Struct
typedef struct {
    char Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Use: %s <Path file PE>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        perror("Error load file");
        return 1;
    }

    // Seek to the start of the Optional Header
    fseek(file, 0x3C, SEEK_SET);
    uint32_t offset;
    fread(&offset, sizeof(offset), 1, file);

    fseek(file, offset + 24, SEEK_SET); // Offset of the Magic field in Optional Header

    uint16_t magic;
    fread(&magic, sizeof(magic), 1, file);

    if (magic == 0x10B) {
        printf("This is a PE32 file.\n\n");
    } else if (magic == 0x20B) {
        printf("This is a PE64 file.\n\n");
    } else {
        printf("Wrong :(((");
    }

    fseek(file, 0, SEEK_SET);

    //DOS Header
    IMAGE_DOS_HEADER dosHeader;
    fread(&dosHeader, sizeof(dosHeader), 1, file);
    if (dosHeader.e_magic != 0x5A4D) {
        printf("File don't PE File.\n");
        fclose(file);
        return 1;
    }
	printf("******* DOS HEADER *******\n");
	printf("\t0x%x\t\tMagic number\n", dosHeader.e_magic);
	printf("\t0x%x\t\tBytes on last page of file\n", dosHeader.e_cblp);
	printf("\t0x%x\t\tPages in file\n", dosHeader.e_cp);
	printf("\t0x%x\t\tRelocations\n", dosHeader.e_crlc);
	printf("\t0x%x\t\tSize of header in paragraphs\n", dosHeader.e_cparhdr);
	printf("\t0x%x\t\tMinimum extra paragraphs needed\n", dosHeader.e_minalloc);
	printf("\t0x%x\t\tMaximum extra paragraphs needed\n", dosHeader.e_maxalloc);
	printf("\t0x%x\t\tInitial (relative) SS value\n", dosHeader.e_ss);
	printf("\t0x%x\t\tInitial SP value\n", dosHeader.e_sp);
	printf("\t0x%x\t\tChecksum\n", dosHeader.e_csum);
	printf("\t0x%x\t\tInitial IP value\n", dosHeader.e_ip);
	printf("\t0x%x\t\tInitial (relative) CS value\n", dosHeader.e_cs);
	printf("\t0x%x\t\tFile address of relocation table\n", dosHeader.e_lfarlc);
	printf("\t0x%x\t\tOverlay number\n", dosHeader.e_ovno);
	printf("\t0x%x\t\tOEM identifier (for e_oeminfo)\n", dosHeader.e_oemid);
	printf("\t0x%x\t\tOEM information; e_oemid specific\n", dosHeader.e_oeminfo);
	printf("\t0x%x\t\tFile address of new exe header\n", dosHeader.e_lfanew);
    fseek(file, dosHeader.e_lfanew, SEEK_SET);

    //PE Header
    uint16_t numSection;
    if (magic == 0x10B) {
        //PE Header
        IMAGE_NT_HEADERS32 imageNTHeaders;
        fread(&imageNTHeaders, sizeof(imageNTHeaders), 1, file);
        // NT Header
        printf("\n******* NT HEADERS *******\n");
	    printf("\t0x%x\t\tSignature\n", imageNTHeaders.Signature);
        // File Header
	    printf("\n**** File Header ****\n");
	    printf("\t0x%x\t\tMachine\n", imageNTHeaders.FileHeader.Machine);
	    printf("\t0x%x\t\tNumber of Sections\n", imageNTHeaders.FileHeader.NumberOfSections);
        numSection = imageNTHeaders.FileHeader.NumberOfSections;
	    printf("\t0x%x\tTime Stamp\n", imageNTHeaders.FileHeader.TimeDateStamp);
	    printf("\t0x%x\t\tPointer to Symbol Table\n", imageNTHeaders.FileHeader.PointerToSymbolTable);
	    printf("\t0x%x\t\tNumber of Symbols\n", imageNTHeaders.FileHeader.NumberOfSymbols);
	    printf("\t0x%x\t\tSize of Optional Header\n", imageNTHeaders.FileHeader.SizeOfOptionalHeader);
	    printf("\t0x%x\t\tCharacteristics\n", imageNTHeaders.FileHeader.Characteristics);
        // Optional Header
	    printf("\n**** Optional Header ****\n");
	    printf("\t0x%x\t\tMagic\n", imageNTHeaders.OptionalHeader.Magic);
	    printf("\t0x%x\t\tMajor Linker Version\n", imageNTHeaders.OptionalHeader.MajorLinkerVersion);
	    printf("\t0x%x\t\tMinor Linker Version\n", imageNTHeaders.OptionalHeader.MinorLinkerVersion);
	    printf("\t0x%x\t\tSize Of Code\n", imageNTHeaders.OptionalHeader.SizeOfCode);
	    printf("\t0x%x\t\tSize Of Initialized Data\n", imageNTHeaders.OptionalHeader.SizeOfInitializedData);
	    printf("\t0x%x\t\tSize Of UnInitialized Data\n", imageNTHeaders.OptionalHeader.SizeOfUninitializedData);
	    printf("\t0x%x\t\tAddress Of Entry Point (.text)\n", imageNTHeaders.OptionalHeader.AddressOfEntryPoint);
	    printf("\t0x%x\t\tBase Of Code\n", imageNTHeaders.OptionalHeader.BaseOfCode);
	    printf("\t0x%x\t\tBase Of Data\n", imageNTHeaders.OptionalHeader.BaseOfData);
	    printf("\t0x%x\tImage Base\n", imageNTHeaders.OptionalHeader.ImageBase);
	    printf("\t0x%x\t\tSection Alignment\n", imageNTHeaders.OptionalHeader.SectionAlignment);
	    printf("\t0x%x\t\tFile Alignment\n", imageNTHeaders.OptionalHeader.FileAlignment);
	    printf("\t0x%x\t\tMajor Operating System Version\n", imageNTHeaders.OptionalHeader.MajorOperatingSystemVersion);
	    printf("\t0x%x\t\tMinor Operating System Version\n", imageNTHeaders.OptionalHeader.MinorOperatingSystemVersion);
	    printf("\t0x%x\t\tMajor Image Version\n", imageNTHeaders.OptionalHeader.MajorImageVersion);
	    printf("\t0x%x\t\tMinor Image Version\n", imageNTHeaders.OptionalHeader.MinorImageVersion);
	    printf("\t0x%x\t\tMajor Subsystem Version\n", imageNTHeaders.OptionalHeader.MajorSubsystemVersion);
	    printf("\t0x%x\t\tMinor Subsystem Version\n", imageNTHeaders.OptionalHeader.MinorSubsystemVersion);
	    printf("\t0x%x\t\tWin32 Version Value\n", imageNTHeaders.OptionalHeader.Win32VersionValue);
	    printf("\t0x%x\t\tSize Of Image\n", imageNTHeaders.OptionalHeader.SizeOfImage);
	    printf("\t0x%x\t\tSize Of Headers\n", imageNTHeaders.OptionalHeader.SizeOfHeaders);
	    printf("\t0x%x\t\tCheckSum\n", imageNTHeaders.OptionalHeader.CheckSum);
	    printf("\t0x%x\t\tSubsystem\n", imageNTHeaders.OptionalHeader.Subsystem);
	    printf("\t0x%x\t\tDllCharacteristics\n", imageNTHeaders.OptionalHeader.DllCharacteristics);
	    printf("\t0x%x\tSize Of Stack Reserve\n", imageNTHeaders.OptionalHeader.SizeOfStackReserve);
	    printf("\t0x%x\t\tSize Of Stack Commit\n", imageNTHeaders.OptionalHeader.SizeOfStackCommit);
	    printf("\t0x%x\tSize Of Heap Reserve\n", imageNTHeaders.OptionalHeader.SizeOfHeapReserve);
	    printf("\t0x%x\t\tSize Of Heap Commit\n", imageNTHeaders.OptionalHeader.SizeOfHeapCommit);
	    printf("\t0x%x\t\tLoader Flags\n", imageNTHeaders.OptionalHeader.LoaderFlags);
	    printf("\t0x%x\t\tNumber Of Rva And Sizes\n", imageNTHeaders.OptionalHeader.NumberOfRvaAndSizes);
        //Data Directory
        printf("\n* Data Directories *\n");
        printf("\tEXPORT Table:\t\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[0].Size);
        printf("\tIMPORT Table:\t\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[1].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[1].Size);
        printf("\tRESOURCE Table:\t\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[2].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[2].Size);
        printf("\tEXCEPTION Table:\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[3].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[3].Size);
        printf("\tCERTIFICATE Table:\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[4].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[4].Size);
        printf("\tBASE RELOCATION Table:\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[5].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[5].Size);
        printf("\tDEBUG Directory:\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[6].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[6].Size);
        printf("\tArchitecture Specific Data:\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[7].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[7].Size);
        printf("\tGLOBAL POINTER Register:\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[8].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[8].Size);
        printf("\tTLS Table:\t\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[9].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[9].Size);
        printf("\tLOAD CONFIGURATION Table:\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[10].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[10].Size);
        printf("\tBOUND IMPORT Table:\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[11].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[11].Size);
        printf("\tIMPORT Address Table:\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[12].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[12].Size);
        printf("\tDELAY IMPORT Descriptors:\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[13].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[13].Size);
        printf("\tCLI Header:\t\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[14].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[14].Size);
        printf("\tEntry 16:\t\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[15].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[15].Size);
    } else if (magic == 0x20B) {
        IMAGE_NT_HEADERS64 imageNTHeaders;
        fread(&imageNTHeaders, sizeof(imageNTHeaders), 1, file);
        // NT Header
        printf("\n******* NT HEADERS *******\n");
	    printf("\t0x%x\t\tSignature\n", imageNTHeaders.Signature);
        // File Header
	    printf("\n**** File Header ****\n");
	    printf("\t0x%x\t\tMachine\n", imageNTHeaders.FileHeader.Machine);
	    printf("\t0x%x\t\tNumber of Sections\n", imageNTHeaders.FileHeader.NumberOfSections);
        numSection = imageNTHeaders.FileHeader.NumberOfSections;
	    printf("\t0x%x\tTime Stamp\n", imageNTHeaders.FileHeader.TimeDateStamp);
	    printf("\t0x%x\t\tPointer to Symbol Table\n", imageNTHeaders.FileHeader.PointerToSymbolTable);
	    printf("\t0x%x\t\tNumber of Symbols\n", imageNTHeaders.FileHeader.NumberOfSymbols);
	    printf("\t0x%x\t\tSize of Optional Header\n", imageNTHeaders.FileHeader.SizeOfOptionalHeader);
	    printf("\t0x%x\t\tCharacteristics\n", imageNTHeaders.FileHeader.Characteristics);
        // Optional Header
	    printf("\n**** Optional Header ****\n");
	    printf("\t0x%x\t\tMagic\n", imageNTHeaders.OptionalHeader.Magic);
	    printf("\t0x%x\t\tMajor Linker Version\n", imageNTHeaders.OptionalHeader.MajorLinkerVersion);
	    printf("\t0x%x\t\tMinor Linker Version\n", imageNTHeaders.OptionalHeader.MinorLinkerVersion);
	    printf("\t0x%x\tSize Of Code\n", imageNTHeaders.OptionalHeader.SizeOfCode);
	    printf("\t0x%x\tSize Of Initialized Data\n", imageNTHeaders.OptionalHeader.SizeOfInitializedData);
	    printf("\t0x%x\t\tSize Of UnInitialized Data\n", imageNTHeaders.OptionalHeader.SizeOfUninitializedData);
	    printf("\t0x%x\tAddress Of Entry Point (.text)\n", imageNTHeaders.OptionalHeader.AddressOfEntryPoint);
	    printf("\t0x%x\t\tBase Of Code\n", imageNTHeaders.OptionalHeader.BaseOfCode);
	    printf("\t0x%x\tImage Base\n", imageNTHeaders.OptionalHeader.ImageBase);
	    printf("\t0x%x\t\tSection Alignment\n", imageNTHeaders.OptionalHeader.SectionAlignment);
	    printf("\t0x%x\t\tFile Alignment\n", imageNTHeaders.OptionalHeader.FileAlignment);
	    printf("\t0x%x\t\tMajor Operating System Version\n", imageNTHeaders.OptionalHeader.MajorOperatingSystemVersion);
	    printf("\t0x%x\t\tMinor Operating System Version\n", imageNTHeaders.OptionalHeader.MinorOperatingSystemVersion);
	    printf("\t0x%x\t\tMajor Image Version\n", imageNTHeaders.OptionalHeader.MajorImageVersion);
	    printf("\t0x%x\t\tMinor Image Version\n", imageNTHeaders.OptionalHeader.MinorImageVersion);
	    printf("\t0x%x\t\tMajor Subsystem Version\n", imageNTHeaders.OptionalHeader.MajorSubsystemVersion);
	    printf("\t0x%x\t\tMinor Subsystem Version\n", imageNTHeaders.OptionalHeader.MinorSubsystemVersion);
	    printf("\t0x%x\t\tWin32 Version Value\n", imageNTHeaders.OptionalHeader.Win32VersionValue);
	    printf("\t0x%x\tSize Of Image\n", imageNTHeaders.OptionalHeader.SizeOfImage);
	    printf("\t0x%x\t\tSize Of Headers\n", imageNTHeaders.OptionalHeader.SizeOfHeaders);
	    printf("\t0x%x\tCheckSum\n", imageNTHeaders.OptionalHeader.CheckSum);
	    printf("\t0x%x\t\tSubsystem\n", imageNTHeaders.OptionalHeader.Subsystem);
	    printf("\t0x%x\t\tDllCharacteristics\n", imageNTHeaders.OptionalHeader.DllCharacteristics);
	    printf("\t0x%x\tSize Of Stack Reserve\n", imageNTHeaders.OptionalHeader.SizeOfStackReserve);
	    printf("\t0x%x\t\tSize Of Stack Commit\n", imageNTHeaders.OptionalHeader.SizeOfStackCommit);
	    printf("\t0x%x\tSize Of Heap Reserve\n", imageNTHeaders.OptionalHeader.SizeOfHeapReserve);
	    printf("\t0x%x\t\tSize Of Heap Commit\n", imageNTHeaders.OptionalHeader.SizeOfHeapCommit);
	    printf("\t0x%x\t\tLoader Flags\n", imageNTHeaders.OptionalHeader.LoaderFlags);
	    printf("\t0x%x\t\tNumber Of Rva And Sizes\n", imageNTHeaders.OptionalHeader.NumberOfRvaAndSizes);
        //Data Directory
        printf("\n* Data Directories *\n");
        printf("\tEXPORT Table:\t\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[0].Size);
        printf("\tIMPORT Table:\t\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[1].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[1].Size);
        printf("\tRESOURCE Table:\t\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[2].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[2].Size);
        printf("\tEXCEPTION Table:\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[3].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[3].Size);
        printf("\tCERTIFICATE Table:\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[4].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[4].Size);
        printf("\tBASE RELOCATION Table:\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[5].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[5].Size);
        printf("\tDEBUG Directory:\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[6].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[6].Size);
        printf("\tArchitecture Specific Data:\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[7].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[7].Size);
        printf("\tGLOBAL POINTER Register:\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[8].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[8].Size);
        printf("\tTLS Table:\t\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[9].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[9].Size);
        printf("\tLOAD CONFIGURATION Table:\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[10].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[10].Size);
        printf("\tBOUND IMPORT Table:\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[11].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[11].Size);
        printf("\tIMPORT Address Table:\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[12].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[12].Size);
        printf("\tDELAY IMPORT Descriptors:\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[13].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[13].Size);
        printf("\tCLI Header:\t\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[14].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[14].Size);
        printf("\tEntry 16:\t\t\t RVA: 0x%x;\t Size: 0x%x\n", imageNTHeaders.OptionalHeader.DataDirectory[15].VirtualAddress, imageNTHeaders.OptionalHeader.DataDirectory[15].Size);
    }
  
    // Section Header
	printf("\n******* SECTION HEADERS *******\n");
    IMAGE_SECTION_HEADER sectionHeader;
    for (int i = 0; i < numSection; i++){
        fread(&sectionHeader, sizeof(sectionHeader), 1, file);
        printf("\t%s\n", sectionHeader.Name);
		printf("\t\t0x%x\t\tVirtual Size\n", sectionHeader.Misc.VirtualSize);
		printf("\t\t0x%x\t\tVirtual Address\n", sectionHeader.VirtualAddress);
		printf("\t\t0x%x\t\tSize Of Raw Data\n", sectionHeader.SizeOfRawData);
		printf("\t\t0x%x\t\tPointer To Raw Data\n", sectionHeader.PointerToRawData);
		printf("\t\t0x%x\t\tPointer To Relocations\n", sectionHeader.PointerToRelocations);
		printf("\t\t0x%x\t\tPointer To Line Numbers\n", sectionHeader.PointerToLinenumbers);
		printf("\t\t0x%x\t\tNumber Of Relocations\n", sectionHeader.NumberOfRelocations);
		printf("\t\t0x%x\t\tNumber Of Line Numbers\n", sectionHeader.NumberOfLinenumbers);
		printf("\t\t0x%x\tCharacteristics\n", sectionHeader.Characteristics);
    }

    fclose(file);
    return 0;
}
