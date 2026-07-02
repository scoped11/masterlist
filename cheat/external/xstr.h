#pragma once
#include <string>
#include <initializer_list>

// Runtime XOR string decryption - prevents plaintext strings in binary
constexpr unsigned char _XKEY = 0x5A;

inline std::string xdec(std::initializer_list<unsigned char> enc) {
    std::string s;
    s.reserve(enc.size());
    for (unsigned char b : enc) s += (char)(b ^ _XKEY);
    return s;
}

#define XS(...) xdec({__VA_ARGS__})
