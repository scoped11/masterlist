#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <AclAPI.h>
#pragma comment(lib,"advapi32.lib")

int main() {
    // Try with SDDL helper - open the device and query its security
    HANDLE h = CreateFileA("\\\\.\\Asusgio2", READ_CONTROL,
        FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    printf("READ_CONTROL open: h=%p err=%u\n", h, GetLastError());
    if (h == INVALID_HANDLE_VALUE) {
        // Try from kernel perspective - get SD via NtQuerySecurityObject
        return 0;
    }
    PSECURITY_DESCRIPTOR pSD = NULL;
    PSID owner = NULL; BOOL defOwner;
    PSID group = NULL; BOOL defGroup;
    PACL dacl = NULL; BOOL defDacl;
    GetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, 
        &owner, &group, &dacl, NULL, &pSD);
    if (pSD) {
        LPSTR sddl = NULL;
        ConvertSecurityDescriptorToStringSecurityDescriptorA(pSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, NULL);
        printf("SDDL: %s\n", sddl ? sddl : "(null)");
        LocalFree(sddl); LocalFree(pSD);
    }
    CloseHandle(h);
    return 0;
}
