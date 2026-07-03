#include "features.h"
#include "security.h"
#include <thread>
#pragma comment(linker, "/MANIFESTUAC:\"level='asInvoker' uiAccess='false'\"")

extern DWORD64 baseAddress;
extern uintptr_t GET_ROOT_DOMAIN_OFFSET;

// ---------------------------------------------------------------------------
// main() — entry point for the Unturned SWHE external cheat.
//
// Startup sequence:
//   1. Security::Init()       — anti-debug / integrity checks
//   2. Memory::init()         — attach to Unturned.exe via SWHE (Shared
//                                Window Handle Engine — usermode read/write
//                                through a shared section)
//   3. Memory::resolve_mono() — locate mono_get_root_domain export inside
//                                mono-2.0-bdwgc.dll to bootstrap Mono API
//   4. Classes::init()        — walk the Mono image to resolve MonoClass*
//                                pointers for every game class we need
//   5. Offsets::init()        — call find_field() on each MonoClass to get
//                                field offsets (no hardcoded addresses)
//   6. Wait for server        — poll Provider.isConnected until the player
//                                has joined a server
//   7. Wait for localPlayer   — poll Player._localPlayer until it is set
//   8. Overlay thread         — spawns a DirectX overlay for ESP rendering
//   9. Feature loop           — polls hotkeys, runs Features::Update() at
//                                ~100 Hz with jittered sleep
//  10. Cleanup                — resets movement multipliers, fullbright,
//                                FOV, then shuts down security + overlay
// ---------------------------------------------------------------------------

int main()
{
    Log("=== Unturned SWHE External ===");

    // --- Step 1: Security layer (anti-debug, integrity) ---
    if (!Security::Init()) return 1;
    Log("Security layer active");

    // --- Step 2: Attach to Unturned via SWHE ---
    Memory::init();

    if (!g_swhe_ready)
    {
        Log("SWHE init failed — make sure Unturned is running");
        system("pause");
        return 1;
    }

    Log("Attached to Unturned.exe via SWHE");
    Log("Resolving classes...");

    // --- Steps 3-4: Resolve Mono runtime and game classes ---
    // Retry loop handles the case where Mono hasn't fully initialized yet
    // (e.g., game is still loading assemblies).
    while (true)
    {
        if (!baseAddress || !GET_ROOT_DOMAIN_OFFSET)
            Memory::resolve_mono();
        Classes::init();
        if (Classes::Player && Classes::Provider)
            break;
        if (GetAsyncKeyState(VK_END) & 1) return 0;
        Log("Mono not ready yet, retrying in 2s...");
        Sleep(2000);
    }

    // --- Step 5: Resolve field offsets via Mono reflection ---
    Log("Resolving offsets...");
    Offsets::init();

    // Warn if critical offsets failed to resolve (game version mismatch).
    if (!Offsets::_look || !Offsets::_yaw || !Offsets::_pitch)
        Log("WARNING: Look/yaw/pitch offsets missing");
    if (!Offsets::_life || !Offsets::_health)
        Log("WARNING: Life/health offsets missing");
    if (!Offsets::_clients)
        Log("WARNING: Clients offset missing");

    // --- Step 6: Wait for server connection ---
    if (Offsets::_isConnected)
    {
        Log("Waiting for server connection...");
        while (!SDG::Provider::isConnected())
        {
            if (GetAsyncKeyState(VK_END) & 1) return 0;
            Sleep(1000);
            printf(".");
        }
        printf("\n");
    }
    else
    {
        // Fallback if _isConnected offset was not found — blind wait.
        Log("_isConnected offset missing - waiting 3s...");
        Sleep(3000);
    }

    // --- Step 7: Wait for local player to be assigned ---
    Log("Waiting for local player...");
    SDG::Player* localPlayer = nullptr;
    while (!(localPlayer = Features::GetLocalPlayer()))
    {
        if (GetAsyncKeyState(VK_END) & 1) return 0;
        Sleep(500);
    }

    Log("Local player: %p", localPlayer);

    // --- Step 8: Launch overlay (DirectX ESP rendering thread) ---
    std::thread overlayThread(Overlay::Run);
    overlayThread.detach();

    // --- Step 9: Main feature loop ---
    Log("Press END to exit.");
    Sleep(300);
    Config::PrintMenu();

    while (true)
    {
        if (GetAsyncKeyState(VK_END) & 1)
            break;

        // Pause features if disconnected from server.
        if (Offsets::_isConnected && !SDG::Provider::isConnected())
        {
            Sleep(1000);
            continue;
        }

        // Re-read local player each tick in case it changed (respawn, etc.).
        localPlayer = Features::GetLocalPlayer();
        if (!localPlayer)
        {
            Sleep(500);
            continue;
        }

        Config::ProcessHotkeys();
        Features::Update(localPlayer);

        // Jittered sleep: 3-9 ms — avoids a perfectly periodic read pattern.
        Sleep(3 + (GetTickCount() % 7));
    }

    // --- Step 10: Cleanup ---
    Log("Shutting down...");
    Security::Shutdown();
    Overlay::Shutdown();
    Sleep(200);

    // Reset any modified movement multipliers back to defaults.
    auto lp = Features::GetLocalPlayer();
    if (lp && Offsets::_movement)
    {
        auto mv = lp->movement();
        if (mv && (uintptr_t)mv > 0x10000)
        {
            if (Offsets::pluginSpeedMultiplier) mv->pluginSpeedMultiplier_set(1.0f);
            if (Offsets::pluginJumpMultiplier) mv->pluginJumpMultiplier_set(1.0f);
            if (Offsets::pluginGravityMultiplier) mv->pluginGravityMultiplier_set(1.0f);
        }

        // Reset fall damage multiplier on the clothing component.
        if (Offsets::_clothing && Offsets::fallingDamageMultiplier)
        {
            uintptr_t clothingPtr = read<uintptr_t>((uintptr_t)lp + Offsets::_clothing);
            if (clothingPtr && clothingPtr > 0x10000)
                write<float>(1.0f, clothingPtr + Offsets::fallingDamageMultiplier);
        }
    }

    // Restore fullbright and FOV to their original values.
    Config::fullbright = false;
    Features::UpdateFullbright();
    Config::fovChanger = false;
    Features::UpdateFOVChanger();

    return 0;
}
