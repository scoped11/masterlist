#include <stdlib.h>
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"advapi32.lib")

typedef struct tagSH {
    ULONG   ProcessId;
    UCHAR   ObjectTypeNumber;
    UCHAR   Flags;
    USHORT  Handle;
    PVOID   Object;
    ACCESS_MASK GrantedAccess;
} SH;
typedef struct tagSHI { ULONG Count; SH H[1]; } SHI;

static void EnableDebug(void) {
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &tok)) return;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid);
    AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(tok);
}

typedef struct tagCK {
    DWORD c, sc, cbIn, cbOut, fFlags; int rc;
    char mg[16]; DWORD rv, mv;
} CK;

int main(int argc, char* argv[]) {
    DWORD pid = argc > 1 ? (DWORD)atoi(argv[1]) : 0;
    if (!pid) { puts("Usage: probe.exe <pid>"); return 1; }
    EnableDebug();

    HANDLE hp = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!hp) { printf("OpenProcess(%u) err=%u\n", (unsigned)pid, (unsigned)GetLastError()); return 1; }
    printf("Opened process handle %p\n", (void*)hp);

    // Allocate buffer for handle list
    ULONG sz = 1024 * 1024;
    SHI* info = NULL;
    NTSTATUS st;
    for (;;) {
        info = (SHI*)realloc(info, sz);
        if (!info) { puts("OOM"); return 1; }
        st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, info, sz, &sz);
        if (st == 0) break;
        if (st != (NTSTATUS)0xC0000004UL) { printf("NtQSI st=0x%X\n", (unsigned)st); return 1; }
        sz += 65536;
    }
    printf("Handle count: %u\n", (unsigned)info->Count);

    int tried = 0;
    for (ULONG i = 0; i < info->Count; i++) {
        if (info->H[i].ProcessId != pid) continue;
        tried++;
        HANDLE dup = NULL;
        if (!DuplicateHandle(hp, (HANDLE)(ULONG_PTR)info->H[i].Handle,
                             GetCurrentProcess(), &dup,
                             0, FALSE, DUPLICATE_SAME_ACCESS)) continue;

        // Try COOKIE IOCTL with two different codes
        static const DWORD ioc[] = { 0x00228004UL, 0x00220004UL };
        for (int j = 0; j < 2; j++) {
            CK req; memset(&req, 0, sizeof(req));
            memcpy(req.mg, "The Magic Word!", 16);
            req.cbIn = sizeof(req); req.cbOut = 64;
            req.rv = 0x00070002UL; req.mv = 0x00070000UL;
            char resp[256]; memset(resp, 0, sizeof(resp));
            DWORD ret = 0;
            BOOL ok = DeviceIoControl(dup, ioc[j], &req, sizeof(req),
                                      resp, (DWORD)sizeof(resp), &ret, NULL);
            DWORD err = GetLastError();
            // Filter: only print if not "wrong ioctl" errors
            if (ok || (err != ERROR_INVALID_FUNCTION && err != ERROR_NOT_SUPPORTED && err != 1)) {
                printf("  H[0x%04X] acc=0x%08X ioc=0x%08X ok=%d err=%u ret=%u\n",
                    (unsigned)info->H[i].Handle,
                    (unsigned)info->H[i].GrantedAccess,
                    (unsigned)ioc[j], (int)ok, (unsigned)err, (unsigned)ret);
                if (ok) {
                    DWORD* r = (DWORD*)resp;
                    printf("    resp: rc=%d ck=0x%08X sck=0x%08X\n",
                        *(int*)(resp+20), (unsigned)r[6], (unsigned)r[7]);
                }
            }
        }
        CloseHandle(dup);
    }
    printf("Tried %d handles from PID %u\n", tried, (unsigned)pid);
    free(info);
    CloseHandle(hp);
    return 0;
}

