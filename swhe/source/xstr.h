#pragma once
#include <string>
#include <initializer_list>

// ---------------------------------------------------------------------------
// XOR string encryption — prevents plaintext strings from appearing in the
// binary's .rdata section.
//
// Usage:
//   At compile time, pre-XOR each character with _XKEY (0x5A) and pass
//   the resulting bytes to XS():
//     XS(0x12, 0x3F, ...)   ->   xdec({0x12, 0x3F, ...})
//
//   At runtime, xdec() XORs each byte back with 0x5A to recover the
//   original ASCII string.
//
// This is a basic anti-static-analysis measure — it defeats naive string
// scanning in disassemblers / YARA rules but is trivially reversible at
// runtime.  The key is a single constant byte (0x5A), so this is
// obfuscation, not real encryption.
// ---------------------------------------------------------------------------

// Runtime XOR string decryption - prevents plaintext strings in binary
constexpr unsigned char _XKEY = 0x5A;

// Decrypt an XOR-encoded byte sequence back to a std::string.
inline std::string xdec(std::initializer_list<unsigned char> enc) {
    std::string s;
    s.reserve(enc.size());
    for (unsigned char b : enc) s += (char)(b ^ _XKEY);
    return s;
}

// Convenience macro: XS(byte1, byte2, ...) -> decrypted std::string at runtime.
#define XS(...) xdec({__VA_ARGS__})
