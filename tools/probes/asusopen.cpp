#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")

typedef NTSTATUS(NTAPI* PfnNtDevIo)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);

static HANDLE TryOpen(const wchar_t* path, DWORD access) {
    UNICODE_STRING us;
    us.Buffer = (PWSTR)path;
    us.Length = (USHORT)(wcslen(path) * 2);
    us.MaximumLength = us.Length;
    OBJECT_ATTRIBUTES oa = {sizeof(oa), 0, &us, 0x40, 0, 0};
    IO_STATUS_BLOCK isb = {0};
    HANDLE h = INVALID_HANDLE_VALUE;
    NtCreateFile(&h, access, &oa, &isb, 0, 0, FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN, 0, 0, 0);
    return h;
}

int main() {
    PfnNtDevIo NtDevIo = (PfnNtDevIo)GetProcAddress(GetModuleHandleA("ntdll"), "NtDeviceIoControlFile");
    HANDLE h;

    // Try various paths
    const wchar_t* paths[] = {
        L"\\Device\\Asusgio2", L"\\DosDevices\\Asusgio2", 
        L"\\??\\Asusgio2", L"\\GLOBAL??\\Asusgio2", 0
    };
    DWORD accesses[] = {
        GENERIC_READ|GENERIC_WRITE, GENERIC_READ, FILE_READ_DATA|FILE_WRITE_DATA, SYNCHRONIZE, 0
    };

    for (int pi = 0; paths[pi]; pi++) {
        for (int ai = 0; accesses[ai]; ai++) {
            h = TryOpen(paths[pi], accesses[ai]);
            if (h != INVALID_HANDLE_VALUE) {
                printf("Opened %ls acc=0x%X h=%p\n", paths[pi], accesses[ai], h);
                CloseHandle(h);
            }
        }
    }

    // Also try Win32 API
    HANDLE h2 = CreateFileA("\\\\.\\Asusgio2", GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    printf("Win32 open GENERIC_R|W: %s err=%u\n", h2!=INVALID_HANDLE_VALUE?"OK":"FAIL", GetLastError());
    if (h2 != INVALID_HANDLE_VALUE) CloseHandle(h2);
    return 0;
}
