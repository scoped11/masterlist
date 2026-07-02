// Smoke test: verify NalDrv case 15 (read DWORD from kernel VA) works correctly
// without touching HAL or writing anything.
#include <Windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

static constexpr DWORD NAL_IOCTL = 0x80862007;
static constexpr uint64_t NAL_CASE_READ_DWORD = 15;

#pragma pack(push,1)
struct NalOp {
    uint64_t case_number;
    uint64_t pad;
    uint64_t value;    // +0x10: read result
    uint64_t address;  // +0x18: kernel VA
    uint64_t writeVal; // +0x20
    uint64_t size;     // +0x28
};
#pragma pack(pop)

int main() {
    HANDLE h = CreateFileA("\\\\.\\Nal", GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        std::cerr << "Open failed: " << GetLastError() << "\n"; return 1;
    }

    // Get ntoskrnl base
    auto NtQSI = (NTSTATUS(NTAPI*)(ULONG,PVOID,ULONG,PULONG))
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    ULONG needed = 0;
    NtQSI(0x0B, nullptr, 0, &needed); needed += 0x1000;
    std::vector<uint8_t> buf(needed);
    NtQSI(0x0B, buf.data(), needed, &needed);
    struct MI { HANDLE s; PVOID mb,ib; ULONG is,fl; USHORT lo,io,lc,on; char fp[256]; };
    struct ML { ULONG n; MI m[1]; };
    auto* ml = (ML*)buf.data();
    uint64_t kbase = 0;
    for (ULONG i=0;i<ml->n;++i)
        if (_stricmp(ml->m[i].fp+ml->m[i].on,"ntoskrnl.exe")==0)
            { kbase=(uint64_t)ml->m[i].ib; break; }
    std::cout << "ntoskrnl base: 0x" << std::hex << kbase << "\n";

    // Read first 8 bytes of ntoskrnl (MZ header) to verify kernel VA read works
    HMODULE hNtos = LoadLibraryExA("ntoskrnl.exe",nullptr,DONT_RESOLVE_DLL_REFERENCES);
    uint64_t expected = 0;
    memcpy(&expected, hNtos, 8);  // from disk image
    FreeLibrary(hNtos);

    // Read via NalDrv case 15
    uint64_t got = 0;
    for (int i=0;i<2;++i) {
        NalOp op{};
        op.case_number = NAL_CASE_READ_DWORD;
        op.address = kbase + i*4;
        DWORD ret=0;
        DeviceIoControl(h, NAL_IOCTL, &op, sizeof(op), &op, sizeof(op), &ret, nullptr);
        uint32_t dw = (uint32_t)(op.value & 0xFFFFFFFF);
        got |= ((uint64_t)dw << (i*32));
        std::cout << "Read[" << i << "] kva=0x" << std::hex << (kbase+i*4)
                  << " => 0x" << dw << "\n";
    }
    std::cout << "Got:      0x" << std::hex << got << "\n";
    std::cout << "Expected: 0x" << std::hex << expected << "\n";
    std::cout << (got==expected ? "[PASS] kernel VA read works!\n" : "[FAIL] mismatch\n");
    CloseHandle(h);
    return 0;
}
