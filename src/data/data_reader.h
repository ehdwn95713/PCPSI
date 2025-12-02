#pragma once
#include <vector>
#include <string>
#include <cstdint>

// Reads a text file where each line is a uint32_t and returns as a vector
std::vector<uint32_t> read_uint32_file(const std::string& path);
