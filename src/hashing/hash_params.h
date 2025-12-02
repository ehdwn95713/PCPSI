#pragma once
#include <cstdint>
#include <string>

// Common hash function parameter struct
struct HashParams {
    uint64_t c0, c1, c2, c3;
    uint64_t prime;
    uint64_t seed;
    uint64_t mod;
    std::string name;
};
