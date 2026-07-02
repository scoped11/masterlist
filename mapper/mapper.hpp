#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <functional>

// ── Kernel primitive interface ────────────────────────────────────────────────
// Implement these three functions using whatever primitive your challenge gives
// you (BYOVD IOCTL, exploit, etc.), then pass them into ManualMapper.
struct KernelPrimitives {
    // Allocate executable kernel memory; returns kernel VA or 0 on failure
    std::function<uint64_t(size_t size)> AllocateKernelMemory;

    // Copy `size` bytes from `src` (user VA) into kernel VA `dst`
    std::function<bool(uint64_t dst, const void* src, size_t size)> WriteKernelMemory;

    // Copy `size` bytes from kernel VA `src` into `dst` (user VA)
    std::function<bool(void* dst, uint64_t src, size_t size)> ReadKernelMemory;

    // Physical read (optional, for self-referencing PML4 PteBase scan)
    std::function<bool(void* dst, uint64_t physAddr, size_t size)> ReadPhysicalMemory;
    uint64_t cr3 = 0;

    // Update internal CR3 used by Read/WriteKernelMemory lambdas
    std::function<void(uint64_t newCr3)> UpdateCR3;
};

// ── Result ────────────────────────────────────────────────────────────────────
struct MapResult {
    bool        success    = false;
    uint64_t    imageBase  = 0;   // kernel VA of mapped image
    uint64_t    entryPoint = 0;   // kernel VA of DriverEntry
    std::string error;
};

// ── Public API ────────────────────────────────────────────────────────────────
MapResult ManualMap(const std::vector<uint8_t>& driverImage,
                    const KernelPrimitives&     prim);
