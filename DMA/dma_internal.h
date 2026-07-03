#pragma once
#include "dma_inject.h"
#include "dma_overlay.h"
#include "../external/game_math.h"

namespace InternalESP
{
	// shared data layout — written by PC2 via DMA, read by shellcode on PC1
	// lives at the start of the code cave
	#pragma pack(push, 1)
	struct SharedData
	{
		uint32_t magic;              // 0xC0DE0001 when valid
		uint32_t playerCount;
		uint64_t gameHwnd;           // HWND as uint64
		int32_t  screenW;
		int32_t  screenH;
		float    localYaw;
		float    localPitch;
		float    localFov;
		float    camX, camY, camZ;

		struct PlayerEntry
		{
			float screenX, screenY;
			float boxW, boxH;
			float health;            // 0.0 - 100.0
			uint32_t color;          // BGR
			float distance;
			uint8_t hasName;
			char name[31];
		} players[48]; // 48 * 56 = 2688

		// function pointer table — resolved by PC2 before injection
		uint64_t fn_GetDC;
		uint64_t fn_ReleaseDC;
		uint64_t fn_SelectObject;
		uint64_t fn_Rectangle;
		uint64_t fn_CreatePen;
		uint64_t fn_DeleteObject;
		uint64_t fn_SetBkMode;
		uint64_t fn_SetTextColor;
		uint64_t fn_TextOutA;
		uint64_t fn_MoveToEx;
		uint64_t fn_LineTo;
		uint64_t fn_CreateSolidBrush;
		uint64_t fn_FillRect;
		uint64_t fn_GetStockObject;
		uint64_t originalPresent;    // saved original IDXGISwapChain::Present
		uint64_t swapChainAddr;      // for verification
	};
	#pragma pack(pop)

	static_assert(offsetof(SharedData, fn_GetDC) < 4096, "SharedData too large");

	inline uintptr_t caveBase = 0;
	inline uintptr_t shellcodeAddr = 0;
	inline uintptr_t swapChain = 0;
	inline uintptr_t originalPresent = 0;

	// x64 Present hook shellcode
	// calling convention: rcx = this (IDXGISwapChain*), rdx = SyncInterval, r8 = Flags
	// the shellcode reads SharedData from [rip - relative], draws ESP with GDI, then calls original Present
	//
	// layout in memory:
	//   [0x0000 .. sizeof(SharedData)]  = SharedData (updated by PC2)
	//   [sizeof(SharedData) .. +shellcodeSize] = shellcode (this array)
	//
	inline const uint8_t HOOK_SHELLCODE[] = {
		// ---- prologue ----
		0x48, 0x89, 0x5C, 0x24, 0x08,             // mov [rsp+8], rbx          ; save non-vol
		0x48, 0x89, 0x6C, 0x24, 0x10,             // mov [rsp+10h], rbp
		0x48, 0x89, 0x74, 0x24, 0x18,             // mov [rsp+18h], rsi
		0x48, 0x89, 0x7C, 0x24, 0x20,             // mov [rsp+20h], rdi
		0x41, 0x54,                                 // push r12
		0x41, 0x55,                                 // push r13
		0x41, 0x56,                                 // push r14
		0x48, 0x83, 0xEC, 0x68,                     // sub rsp, 68h             ; stack frame

		// save Present args
		0x48, 0x89, 0x4C, 0x24, 0x40,             // mov [rsp+40h], rcx       ; swap chain this
		0x89, 0x54, 0x24, 0x48,                     // mov [rsp+48h], edx       ; SyncInterval
		0x44, 0x89, 0x44, 0x24, 0x4C,             // mov [rsp+4Ch], r8d       ; Flags

		// ---- calculate SharedData base ----
		// SharedData is at (caveBase), shellcode is at (caveBase + sizeof(SharedData))
		// we use a RIP-relative LEA to find ourselves, then subtract the shellcode offset
		0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00, // lea rsi, [rip+0]         ; rsi = &next_insn
		// fixup: subtract (sizeof(SharedData) + offset_of_this_lea + 7) to get SharedData*
		// we'll fixup this displacement at injection time

		// ---- check magic ----
		0x81, 0x3E, 0x01, 0x00, 0xDE, 0xC0,       // cmp dword [rsi], 0xC0DE0001
		0x0F, 0x85, 0x00, 0x01, 0x00, 0x00,       // jne skip_draw (fixup)

		// ---- get HWND from SharedData ----
		0x48, 0x8B, 0x4E, 0x08,                     // mov rcx, [rsi+8]         ; hwnd
		0x48, 0x85, 0xC9,                           // test rcx, rcx
		0x0F, 0x84, 0xF3, 0x00, 0x00, 0x00,       // jz skip_draw

		// ---- GetDC(hwnd) ----
		0xFF, 0x96, 0x00, 0x00, 0x00, 0x00,       // call [rsi + fn_GetDC_off] ; fixup
		0x48, 0x85, 0xC0,                           // test rax, rax
		0x0F, 0x84, 0xE3, 0x00, 0x00, 0x00,       // jz skip_draw
		0x48, 0x89, 0xC7,                           // mov rdi, rax             ; rdi = hdc

		// ---- SetBkMode(hdc, TRANSPARENT=1) ----
		0x48, 0x89, 0xF9,                           // mov rcx, rdi
		0xBA, 0x01, 0x00, 0x00, 0x00,             // mov edx, 1
		0xFF, 0x96, 0x00, 0x00, 0x00, 0x00,       // call [rsi + fn_SetBkMode_off]

		// ---- GetStockObject(NULL_BRUSH=5) for hollow rectangles ----
		0xB9, 0x05, 0x00, 0x00, 0x00,             // mov ecx, 5
		0xFF, 0x96, 0x00, 0x00, 0x00, 0x00,       // call [rsi + fn_GetStockObject_off]
		0x49, 0x89, 0xC6,                           // mov r14, rax             ; r14 = null brush

		// ---- select null brush ----
		0x48, 0x89, 0xF9,                           // mov rcx, rdi
		0x4C, 0x89, 0xF2,                           // mov rdx, r14
		0xFF, 0x96, 0x00, 0x00, 0x00, 0x00,       // call [rsi + fn_SelectObject_off]
		0x49, 0x89, 0xC5,                           // mov r13, rax             ; save old brush

		// ---- CreatePen(PS_SOLID=0, 2, RED=0x0000FF) ----
		0x31, 0xC9,                                 // xor ecx, ecx             ; PS_SOLID
		0xBA, 0x02, 0x00, 0x00, 0x00,             // mov edx, 2               ; width
		0x41, 0xB8, 0xFF, 0x00, 0x00, 0x00,       // mov r8d, 0x0000FF        ; red
		0xFF, 0x96, 0x00, 0x00, 0x00, 0x00,       // call [rsi + fn_CreatePen_off]
		0x49, 0x89, 0xC4,                           // mov r12, rax             ; r12 = pen

		// ---- select pen ----
		0x48, 0x89, 0xF9,                           // mov rcx, rdi
		0x4C, 0x89, 0xE2,                           // mov rdx, r12
		0xFF, 0x96, 0x00, 0x00, 0x00, 0x00,       // call [rsi + fn_SelectObject_off2]

		// ---- draw loop ----
		// ebx = player count, rbp = pointer to players array
		0x8B, 0x5E, 0x04,                           // mov ebx, [rsi+4]         ; playerCount
		0x85, 0xDB,                                 // test ebx, ebx
		0x0F, 0x84, 0x60, 0x00, 0x00, 0x00,       // jz cleanup
		0x83, 0xFB, 0x30,                           // cmp ebx, 48
		0x76, 0x03,                                 // jbe ok_count
		0xBB, 0x30, 0x00, 0x00, 0x00,             // mov ebx, 48
		// ok_count:
		0x48, 0x8D, 0xAE, 0x00, 0x00, 0x00, 0x00, // lea rbp, [rsi + players_off] ; fixup

		// ---- per-player loop ----
		// loop_top:
		0xF3, 0x0F, 0x10, 0x45, 0x08,             // movss xmm0, [rbp+8]      ; boxW
		0x0F, 0x2E, 0xC0,                           // ucomiss xmm0, xmm0      ; NaN check
		0x7A, 0x38,                                 // jp next_player
		0xF3, 0x0F, 0x10, 0x4D, 0x08,             // movss xmm1, [rbp+8]      ; boxW
		0x31, 0xC0,                                 // xor eax, eax
		0x0F, 0x2E, 0xC8,                           // ucomiss xmm1, xmm0      ; boxW > 0?
		0x76, 0x2B,                                 // jbe next_player

		// Rectangle(hdc, left, top, right, bottom)
		0xF3, 0x0F, 0x2C, 0x55, 0x00,             // cvttss2si edx, [rbp+0]   ; screenX = left
		0xF3, 0x0F, 0x2C, 0x45, 0x04,             // cvttss2si eax, [rbp+4]   ; screenY = top
		0x44, 0x8B, 0xC0,                           // mov r8d, eax             ; top
		0xF3, 0x0F, 0x10, 0x45, 0x00,             // movss xmm0, [rbp+0]      ; screenX
		0xF3, 0x0F, 0x58, 0x45, 0x08,             // addss xmm0, [rbp+8]      ; + boxW
		0xF3, 0x0F, 0x2C, 0xC8,                     // cvttss2si ecx, xmm0      ; right
		0x44, 0x8B, 0xC9,                           // mov r9d, ecx
		0xF3, 0x0F, 0x10, 0x45, 0x04,             // movss xmm0, [rbp+4]      ; screenY
		0xF3, 0x0F, 0x58, 0x45, 0x0C,             // addss xmm0, [rbp+0C]     ; + boxH
		0xF3, 0x0F, 0x2C, 0xC0,                     // cvttss2si eax, xmm0      ; bottom
		0x89, 0x44, 0x24, 0x20,                     // mov [rsp+20h], eax       ; 5th arg
		0x48, 0x89, 0xF9,                           // mov rcx, rdi             ; hdc
		0xFF, 0x96, 0x00, 0x00, 0x00, 0x00,       // call [rsi + fn_Rectangle_off] ; fixup

		// next_player:
		0x48, 0x83, 0xC5, 0x38,                     // add rbp, 56              ; sizeof(PlayerEntry)
		0xFF, 0xCB,                                 // dec ebx
		0x0F, 0x85, 0xB4, 0xFF, 0xFF, 0xFF,       // jnz loop_top (fixup — relative back)

		// ---- cleanup ----
		// restore old brush
		0x48, 0x89, 0xF9,                           // mov rcx, rdi
		0x4C, 0x89, 0xEA,                           // mov rdx, r13
		0xFF, 0x96, 0x00, 0x00, 0x00, 0x00,       // call [rsi + fn_SelectObject_off3]

		// delete pen
		0x4C, 0x89, 0xE1,                           // mov rcx, r12
		0xFF, 0x96, 0x00, 0x00, 0x00, 0x00,       // call [rsi + fn_DeleteObject_off]

		// ReleaseDC(hwnd, hdc)
		0x48, 0x8B, 0x4E, 0x08,                     // mov rcx, [rsi+8]         ; hwnd
		0x48, 0x89, 0xFA,                           // mov rdx, rdi             ; hdc
		0xFF, 0x96, 0x00, 0x00, 0x00, 0x00,       // call [rsi + fn_ReleaseDC_off]

		// ---- skip_draw: call original Present ----
		0x48, 0x8B, 0x4C, 0x24, 0x40,             // mov rcx, [rsp+40h]       ; swap chain
		0x8B, 0x54, 0x24, 0x48,                     // mov edx, [rsp+48h]       ; SyncInterval
		0x44, 0x8B, 0x44, 0x24, 0x4C,             // mov r8d, [rsp+4Ch]       ; Flags
		0xFF, 0x96, 0x00, 0x00, 0x00, 0x00,       // call [rsi + originalPresent_off]

		// ---- epilogue ----
		0x48, 0x83, 0xC4, 0x68,                     // add rsp, 68h
		0x41, 0x5E,                                 // pop r14
		0x41, 0x5D,                                 // pop r13
		0x41, 0x5C,                                 // pop r12
		0x48, 0x8B, 0x7C, 0x24, 0x20,             // mov rdi, [rsp+20h]
		0x48, 0x8B, 0x74, 0x24, 0x18,             // mov rsi, [rsp+18h]
		0x48, 0x8B, 0x6C, 0x24, 0x10,             // mov rbp, [rsp+10h]
		0x48, 0x8B, 0x5C, 0x24, 0x08,             // mov rbx, [rsp+08h]
		0xC3,                                       // ret
	};

	constexpr size_t HOOK_SIZE = sizeof(HOOK_SHELLCODE);
	constexpr size_t TOTAL_CAVE_NEEDED = sizeof(SharedData) + HOOK_SIZE + 64;

	// build the final shellcode blob with all offsets fixed up
	inline std::vector<uint8_t> buildShellcode(const SharedData& sharedData)
	{
		size_t dataSize = sizeof(SharedData);
		std::vector<uint8_t> blob(dataSize + HOOK_SIZE);

		memcpy(blob.data(), &sharedData, dataSize);
		memcpy(blob.data() + dataSize, HOOK_SHELLCODE, HOOK_SIZE);

		uint8_t* code = blob.data() + dataSize;

		// fixup the LEA [rip+0] at offset 37 to point back to SharedData
		// LEA rsi, [rip + disp32] — disp32 needs to be -(dataSize + offset_after_lea)
		// the LEA is: 48 8D 35 XX XX XX XX at code+37
		// after the LEA, RIP = caveBase + dataSize + 37 + 7 = caveBase + dataSize + 44
		// we want rsi = caveBase, so disp32 = -(dataSize + 44)
		int32_t leaDisp = -(int32_t)(dataSize + 44);
		memcpy(code + 40, &leaDisp, 4); // offset 37 + 3 for the opcode bytes

		// fixup function call offsets — these are [rsi + offset] calls
		// fn_GetDC is at SharedData offset = offsetof(SharedData, fn_GetDC)
		auto fixupCallRSI = [&](size_t codeOffset, size_t fieldOffset) {
			uint32_t off32 = (uint32_t)fieldOffset;
			memcpy(code + codeOffset, &off32, 4);
		};

		// the call instructions are: FF 96 XX XX XX XX (call [rsi + disp32])
		// locate each one and patch the displacement
		// we do this by searching for the FF 96 pattern and patching in order

		struct CallFixup { size_t searchStart; uint32_t fieldOff; };
		CallFixup fixups[] = {
			{ 70,  (uint32_t)offsetof(SharedData, fn_GetDC) },
			{ 85,  (uint32_t)offsetof(SharedData, fn_SetBkMode) },
			{ 96,  (uint32_t)offsetof(SharedData, fn_GetStockObject) },
			{ 107, (uint32_t)offsetof(SharedData, fn_SelectObject) },
			{ 120, (uint32_t)offsetof(SharedData, fn_CreatePen) },
			{ 133, (uint32_t)offsetof(SharedData, fn_SelectObject) },
			{ 200, (uint32_t)offsetof(SharedData, fn_Rectangle) },
			{ 220, (uint32_t)offsetof(SharedData, fn_SelectObject) },
			{ 228, (uint32_t)offsetof(SharedData, fn_DeleteObject) },
			{ 238, (uint32_t)offsetof(SharedData, fn_ReleaseDC) },
			{ 255, (uint32_t)offsetof(SharedData, originalPresent) },
		};

		// find each FF 96 opcode in the shellcode and patch its disp32
		int fixupIdx = 0;
		for (size_t i = 0; i < HOOK_SIZE - 6 && fixupIdx < (int)(sizeof(fixups)/sizeof(fixups[0])); i++)
		{
			if (code[i] == 0xFF && code[i+1] == 0x96 &&
				code[i+2] == 0x00 && code[i+3] == 0x00 && code[i+4] == 0x00 && code[i+5] == 0x00)
			{
				uint32_t off32 = fixups[fixupIdx].fieldOff;
				memcpy(code + i + 2, &off32, 4);
				fixupIdx++;
			}
		}

		// fixup the LEA rbp, [rsi + players_offset]
		for (size_t i = 0; i < HOOK_SIZE - 7; i++)
		{
			if (code[i] == 0x48 && code[i+1] == 0x8D && code[i+2] == 0xAE &&
				code[i+3] == 0x00 && code[i+4] == 0x00 && code[i+5] == 0x00 && code[i+6] == 0x00)
			{
				uint32_t off32 = (uint32_t)offsetof(SharedData, players);
				memcpy(code + i + 3, &off32, 4);
				break;
			}
		}

		return blob;
	}

	inline bool resolveFunctionPointers(SharedData& sd)
	{
		uintptr_t user32 = DMAInject::findRemoteModule("user32.dll");
		uintptr_t gdi32 = DMAInject::findRemoteModule("gdi32.dll");

		if (!user32 || !gdi32)
		{
			Log("[-] user32 or gdi32 not loaded in target");
			return false;
		}

		Log("[+] user32.dll @ 0x%llX", user32);
		Log("[+] gdi32.dll @ 0x%llX", gdi32);

		sd.fn_GetDC = DMAInject::resolveRemoteExport(user32, "GetDC");
		sd.fn_ReleaseDC = DMAInject::resolveRemoteExport(user32, "ReleaseDC");
		sd.fn_FillRect = DMAInject::resolveRemoteExport(user32, "FillRect");

		sd.fn_SelectObject = DMAInject::resolveRemoteExport(gdi32, "SelectObject");
		sd.fn_Rectangle = DMAInject::resolveRemoteExport(gdi32, "Rectangle");
		sd.fn_CreatePen = DMAInject::resolveRemoteExport(gdi32, "CreatePen");
		sd.fn_DeleteObject = DMAInject::resolveRemoteExport(gdi32, "DeleteObject");
		sd.fn_SetBkMode = DMAInject::resolveRemoteExport(gdi32, "SetBkMode");
		sd.fn_SetTextColor = DMAInject::resolveRemoteExport(gdi32, "SetTextColor");
		sd.fn_TextOutA = DMAInject::resolveRemoteExport(gdi32, "TextOutA");
		sd.fn_MoveToEx = DMAInject::resolveRemoteExport(gdi32, "MoveToEx");
		sd.fn_LineTo = DMAInject::resolveRemoteExport(gdi32, "LineTo");
		sd.fn_CreateSolidBrush = DMAInject::resolveRemoteExport(gdi32, "CreateSolidBrush");
		sd.fn_GetStockObject = DMAInject::resolveRemoteExport(gdi32, "GetStockObject");

		bool ok = sd.fn_GetDC && sd.fn_ReleaseDC && sd.fn_SelectObject &&
			sd.fn_Rectangle && sd.fn_CreatePen && sd.fn_DeleteObject &&
			sd.fn_SetBkMode && sd.fn_GetStockObject;

		if (!ok)
			Log("[-] Failed to resolve one or more GDI functions");
		else
			Log("[+] All GDI function pointers resolved");

		return ok;
	}

	// find the game window HWND by reading Unity's window handle from the process
	inline uintptr_t findUnityHWND()
	{
		// Unity stores its main window HWND in UnityPlayer.dll
		// we find it by scanning for the "UnityWndClass" registered window class
		// via user32.dll's internal window list

		// simpler approach: the swap chain's DXGI_SWAP_CHAIN_DESC contains OutputWindow
		// CDXGISwapChain stores desc internally — read from known offset
		// for DXGI 1.0-1.6, the HWND is typically at swapChainObj+0x98 or nearby
		// we scan the swap chain object for a plausible HWND value

		if (!swapChain) return 0;

		uint8_t scBuf[0x200];
		DMAInject::readBytes(swapChain, scBuf, sizeof(scBuf));

		for (size_t off = 0x40; off < 0x1E0; off += 8)
		{
			uint64_t val = *(uint64_t*)(scBuf + off);
			// HWNDs on 64-bit Windows are small values (< 0x100000 typically)
			// but encoded — let's check with IsWindow on PC2... we can't
			// instead, check if it's a plausible user-mode handle
			if (val > 0x10000 && val < 0x10000000 && (val & 1) == 0)
			{
				// additional check: read a few bytes at val as if it were
				// a window object — not possible cross-machine
				// just return the first plausible one
				Log("[*] Candidate HWND @ SC+0x%zX: 0x%llX", off, val);
			}
		}

		// fallback: use MemProcFS window enumeration
		// VMMDLL doesn't have a window enum API, so we rely on the user providing it
		// or we find it from the swap chain's GetDesc call trace
		return 0;
	}

	// main injection entry point
	inline bool inject()
	{
		Log("=== Internal ESP Injection ===");

		// step 1: find swap chain
		swapChain = DMAInject::findSwapChain();
		if (!swapChain)
		{
			Log("[-] Could not locate IDXGISwapChain. Is the game rendering?");
			return false;
		}

		// step 2: find code cave in Mono JIT pages
		auto cave = DMAInject::findCodeCave(TOTAL_CAVE_NEEDED);
		if (!cave.addr)
		{
			Log("[-] No suitable code cave found (need %zu bytes)", TOTAL_CAVE_NEEDED);
			return false;
		}
		caveBase = cave.addr;
		shellcodeAddr = caveBase + sizeof(SharedData);
		Log("[+] Code cave @ 0x%llX (%zu bytes free)", cave.addr, cave.size);

		// step 3: resolve function pointers
		SharedData sd = {};
		sd.magic = 0; // not valid yet — set after first data write
		sd.screenW = 1920;
		sd.screenH = 1080;
		sd.localFov = 90.0f;

		if (!resolveFunctionPointers(sd))
			return false;

		// step 4: read original Present pointer
		uintptr_t vtable = read<uintptr_t>(swapChain);
		originalPresent = read<uintptr_t>(vtable + 8 * 8); // Present = index 8
		sd.originalPresent = originalPresent;
		sd.swapChainAddr = swapChain;
		Log("[+] Original Present: 0x%llX", originalPresent);

		// step 5: build and write the shellcode blob
		auto blob = buildShellcode(sd);
		DMAInject::writeBytes(caveBase, blob.data(), blob.size());
		Log("[+] Shellcode written to cave (%zu bytes)", blob.size());

		// step 6: hook Present vtable entry
		// IMPORTANT: we overwrite the vtable entry (heap data) not code
		// this avoids code integrity detection
		write<uintptr_t>(shellcodeAddr, vtable + 8 * 8);
		Log("[+] Present hooked -> 0x%llX", shellcodeAddr);

		Log("[+] Internal ESP injection complete");
		Log("[*] HWND must be set via updateSharedData() for drawing to work");
		return true;
	}

	// unhook — restore original Present
	inline void unhook()
	{
		if (!swapChain || !originalPresent) return;

		uintptr_t vtable = read<uintptr_t>(swapChain);
		if (!vtable) return;

		write<uintptr_t>(originalPresent, vtable + 8 * 8);
		Log("[+] Present restored to original");
	}

	// update shared ESP data — called every frame from PC2
	inline void updateSharedData(uint64_t hwnd)
	{
		SharedData sd = {};
		sd.magic = 0xC0DE0001;
		sd.gameHwnd = hwnd;
		sd.screenW = Overlay::screenW;
		sd.screenH = Overlay::screenH;
		sd.localYaw = Overlay::localYaw;
		sd.localPitch = Overlay::localPitch;
		sd.localFov = Config::gameFOV > 10.0f ? Config::gameFOV : 90.0f;
		sd.camX = Overlay::localCamPos.x;
		sd.camY = Overlay::localCamPos.y;
		sd.camZ = Overlay::localCamPos.z;

		// pre-calculate screen-space positions for each player
		int count = 0;
		for (int i = 0; i < Overlay::playerCount && count < 48; i++)
		{
			auto& p = Overlay::players[i];
			if (!p.valid) continue;

			// world-to-screen for feet and head
			vector3 sf, sh;
			bool feetVis = Math::WorldToScreen(p.feetPos, Overlay::localCamPos,
				Overlay::localYaw, Overlay::localPitch, sd.localFov,
				sd.screenW, sd.screenH, sf);
			bool headVis = Math::WorldToScreen(p.headPos, Overlay::localCamPos,
				Overlay::localYaw, Overlay::localPitch, sd.localFov,
				sd.screenW, sd.screenH, sh);

			if (!feetVis || !headVis) continue;

			float boxH = fabsf(sf.y - sh.y);
			float boxW = boxH * 0.45f;

			auto& pe = sd.players[count];
			pe.screenX = sh.x - boxW * 0.5f;
			pe.screenY = sh.y;
			pe.boxW = boxW;
			pe.boxH = boxH;
			pe.health = p.health;
			pe.distance = p.distance;
			pe.color = p.isTarget ? 0x00FFFF : 0x0000FF; // yellow / red (BGR)
			pe.hasName = p.name[0] ? 1 : 0;
			if (pe.hasName) strncpy_s(pe.name, p.name, 30);
			count++;
		}
		sd.playerCount = count;

		// preserve function pointers from the injected blob
		SharedData existing = {};
		DMAInject::readBytes(caveBase, &existing, sizeof(existing));
		sd.fn_GetDC = existing.fn_GetDC;
		sd.fn_ReleaseDC = existing.fn_ReleaseDC;
		sd.fn_SelectObject = existing.fn_SelectObject;
		sd.fn_Rectangle = existing.fn_Rectangle;
		sd.fn_CreatePen = existing.fn_CreatePen;
		sd.fn_DeleteObject = existing.fn_DeleteObject;
		sd.fn_SetBkMode = existing.fn_SetBkMode;
		sd.fn_SetTextColor = existing.fn_SetTextColor;
		sd.fn_TextOutA = existing.fn_TextOutA;
		sd.fn_MoveToEx = existing.fn_MoveToEx;
		sd.fn_LineTo = existing.fn_LineTo;
		sd.fn_CreateSolidBrush = existing.fn_CreateSolidBrush;
		sd.fn_FillRect = existing.fn_FillRect;
		sd.fn_GetStockObject = existing.fn_GetStockObject;
		sd.originalPresent = existing.originalPresent;
		sd.swapChainAddr = existing.swapChainAddr;

		// write updated player data
		DMAInject::writeBytes(caveBase, &sd, sizeof(sd));
	}
}
