# peparser.exe

Phân tích cơ bản các thành phần của một file PE gồm:

- DOS Header
- PE Header: Signature, File Header, Optional Header
- Section Table

Phân tích chi tiết cấu trúc một file PE cơ bản có thể tham khảo ở [đây](https://hackmd.io/@noobmannn/BkSHjNnsp)

### Code

[peparser.c](https://github.com/noobmannn/TrainRev/blob/85047678642a136b087522f53f896f0042a09498/PE%20Parser/Src/peparser.c)

[peparser.exe](https://github.com/noobmannn/TrainRev/blob/85047678642a136b087522f53f896f0042a09498/PE%20Parser/Src/peparser.exe)

### Demo

```
C:\Users\Dell>C:\Users\Dell\Downloads\PE_Parser\peparser.exe C:\Users\Dell\Downloads\vmcode.exe
This is a PE32 file.

******* DOS HEADER *******
        0x5a4d          Magic number
        0x90            Bytes on last page of file
        0x3             Pages in file
        0x0             Relocations
        0x4             Size of header in paragraphs
        0x0             Minimum extra paragraphs needed
        0xffff          Maximum extra paragraphs needed
        0x0             Initial (relative) SS value
        0xb8            Initial SP value
        0x0             Checksum
        0x0             Initial IP value
        0x0             Initial (relative) CS value
        0x40            File address of relocation table
        0x0             Overlay number
        0x0             OEM identifier (for e_oeminfo)
        0x0             OEM information; e_oemid specific
        0x100           File address of new exe header

******* NT HEADERS *******
        0x4550          Signature

**** File Header ****
        0x14c           Machine
        0x5             Number of Sections
        0x5cc9d421      Time Stamp
        0x0             Pointer to Symbol Table
        0x0             Number of Symbols
        0xe0            Size of Optional Header
        0x102           Characteristics

**** Optional Header ****
        0x10b           Magic
        0xe             Major Linker Version
        0x0             Minor Linker Version
        0x2c00          Size Of Code
        0x1a00          Size Of Initialized Data
        0x0             Size Of UnInitialized Data
        0x2f55          Address Of Entry Point (.text)
        0x1000          Base Of Code
        0x4000          Base Of Data
        0x400000        Image Base
        0x1000          Section Alignment
        0x200           File Alignment
        0x6             Major Operating System Version
        0x0             Minor Operating System Version
        0x0             Major Image Version
        0x0             Minor Image Version
        0x6             Major Subsystem Version
        0x0             Minor Subsystem Version
        0x0             Win32 Version Value
        0x8000          Size Of Image
        0x400           Size Of Headers
        0x0             CheckSum
        0x3             Subsystem
        0x8140          DllCharacteristics
        0x100000        Size Of Stack Reserve
        0x1000          Size Of Stack Commit
        0x100000        Size Of Heap Reserve
        0x1000          Size Of Heap Commit
        0x0             Loader Flags
        0x10            Number Of Rva And Sizes

* Data Directories *
        EXPORT Table:                    RVA: 0x0;       Size: 0x0
        IMPORT Table:                    RVA: 0x4944;    Size: 0xa0
        RESOURCE Table:                  RVA: 0x6000;    Size: 0x1e0
        EXCEPTION Table:                 RVA: 0x0;       Size: 0x0
        CERTIFICATE Table:               RVA: 0x0;       Size: 0x0
        BASE RELOCATION Table:           RVA: 0x7000;    Size: 0x2ec
        DEBUG Directory:                 RVA: 0x4350;    Size: 0x70
        Architecture Specific Data:      RVA: 0x0;       Size: 0x0
        GLOBAL POINTER Register:         RVA: 0x0;       Size: 0x0
        TLS Table:                       RVA: 0x0;       Size: 0x0
        LOAD CONFIGURATION Table:        RVA: 0x43c0;    Size: 0x40
        BOUND IMPORT Table:              RVA: 0x0;       Size: 0x0
        IMPORT Address Table:            RVA: 0x4000;    Size: 0xec
        DELAY IMPORT Descriptors:        RVA: 0x0;       Size: 0x0
        CLI Header:                      RVA: 0x0;       Size: 0x0
        Entry 16:                        RVA: 0x0;       Size: 0x0

******* SECTION HEADERS *******
        .text
                0x2a33          Virtual Size
                0x1000          Virtual Address
                0x2c00          Size Of Raw Data
                0x400           Pointer To Raw Data
                0x0             Pointer To Relocations
                0x0             Pointer To Line Numbers
                0x0             Number Of Relocations
                0x0             Number Of Line Numbers
                0x60000020      Characteristics
        .rdata
                0xfae           Virtual Size
                0x4000          Virtual Address
                0x1000          Size Of Raw Data
                0x3000          Pointer To Raw Data
                0x0             Pointer To Relocations
                0x0             Pointer To Line Numbers
                0x0             Number Of Relocations
                0x0             Number Of Line Numbers
                0x40000040      Characteristics
        .data
                0x400           Virtual Size
                0x5000          Virtual Address
                0x200           Size Of Raw Data
                0x4000          Pointer To Raw Data
                0x0             Pointer To Relocations
                0x0             Pointer To Line Numbers
                0x0             Number Of Relocations
                0x0             Number Of Line Numbers
                0xc0000040      Characteristics
        .rsrc
                0x1e0           Virtual Size
                0x6000          Virtual Address
                0x200           Size Of Raw Data
                0x4200          Pointer To Raw Data
                0x0             Pointer To Relocations
                0x0             Pointer To Line Numbers
                0x0             Number Of Relocations
                0x0             Number Of Line Numbers
                0x40000040      Characteristics
        .reloc
                0x2ec           Virtual Size
                0x7000          Virtual Address
                0x400           Size Of Raw Data
                0x4400          Pointer To Raw Data
                0x0             Pointer To Relocations
                0x0             Pointer To Line Numbers
                0x0             Number Of Relocations
                0x0             Number Of Line Numbers
                0x42000040      Characteristics
```
