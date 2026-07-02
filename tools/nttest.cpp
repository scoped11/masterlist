#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"kernel32.lib")

// NtCreateFile is already declared in winternl.h; avoid redeclaration
// NtDeviceIoControlFile is not in winternl.h - declare via GetProcAddress
typedef NTSTATUS (NTAPI *PfnNtDevIo)(HANDLE,HANDLE,PVOID,PVOID,PIO_STATUS_BLOCK,ULONG,PVOID,ULONG,PVOID,ULONG);

#pragma pack(push,1)
struct Hdr { unsigned ck, sck, cbIn, cbOut, fl; int rc; };
struct CookieIn  { Hdr h; char magic[16]; unsigned ver, minVer; };
struct CookieOut { Hdr h; unsigned ck, sck, sver, dver, cfn; unsigned long long psess; };
#pragma pack(pop)

int main() {
    PfnNtDevIo NtDevIo = (PfnNtDevIo)GetProcAddress(GetModuleHandleA("ntdll"), "NtDeviceIoControlFile");

    static const wchar_t kPath[] = L"\\Device\\VBoxDrvU";
    UNICODE_STRING us{(USHORT)(sizeof(kPath)-2),(USHORT)(sizeof(kPath)-2),(PWSTR)kPath};
    OBJECT_ATTRIBUTES oa{sizeof(oa),0,&us,0x40,0,0};
    IO_STATUS_BLOCK isb{};
    HANDLE h = INVALID_HANDLE_VALUE;
    NTSTATUS st = NtCreateFile(&h, GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE, &oa, &isb, 0, 0,
        FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    printf("Open: 0x%08X handle=%p\n", (unsigned)st, h);
    if (st) return 1;

    CookieIn in{}; CookieOut out{};
    in.h.ck    = 0x69726f74u;
    in.h.cbIn  = (unsigned)sizeof(in);   // 48
    in.h.cbOut = (unsigned)sizeof(out);  // 52
    memcpy(in.magic, "The Magic Word!", 16);
    in.ver    = 0x003D0000u;
    in.minVer = 0x00290000u;
    printf("sizeof(in)=%zu sizeof(out)=%zu\n", sizeof(in), sizeof(out));

    IO_STATUS_BLOCK isb2{};
    NTSTATUS st2 = NtDevIo(h, 0, 0, 0, &isb2, 0x00228004, &in, sizeof(in), &out, sizeof(out));
    printf("NtStatus=0x%08X rc=%d resp.ck=0x%08X resp.sck=0x%08X\n",
        (unsigned)st2, out.h.rc, out.ck, out.sck);

    CloseHandle(h);
    return 0;
}
