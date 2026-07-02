#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"kernel32.lib")

typedef NTSTATUS(NTAPI* PfnNtDevIo)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);

int main() {
    FILE* f = fopen("C:\\Users\\K\\Desktop\\PenisFinger\\build\\obj\\asusprobe_out.txt", "w");
    if (!f) f = stdout;
    
    PfnNtDevIo NtDevIo = (PfnNtDevIo)GetProcAddress(GetModuleHandleA("ntdll"), "NtDeviceIoControlFile");
    HANDLE h = CreateFileA("\\\\.\\Asusgio2", GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    fprintf(f, "Asusgio2 open: h=%p err=%u\n", h, GetLastError());
    
    if (h != INVALID_HANDLE_VALUE) {
        DWORD codes[] = {
            0x0022E010, 0x0022E014, 0x0022E018, 0x0022E01C, 0x0022E020,
            0x0022E040, 0x0022E044, 0x0022E050,
            0x0022C008, 0x0022C00C, 0x00226010
        };
        BYTE inBuf[64]={0}; BYTE outBuf[64]={0};
        for (int i = 0; i < 11; i++) {
            IO_STATUS_BLOCK isb = {0};
            NTSTATUS st = NtDevIo(h, 0,0,0, &isb, codes[i], inBuf, sizeof(inBuf), outBuf, sizeof(outBuf));
            fprintf(f, "IOCTL 0x%08X -> 0x%08X\n", codes[i], (unsigned)st);
        }
        CloseHandle(h);
    }
    if (f != stdout) fclose(f);
    return 0;
}
