#include "data_reader.h"
#include <fstream>
#include <iostream>

std::vector<uint32_t> read_uint32_file(const std::string& path) {
    std::vector<uint32_t> result;
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        std::cerr << "Failed to open file: " << path << std::endl;
        return result;
    }
    uint32_t value;
    while (ifs >> value) {
        result.push_back(value);
    }
    return result;
}

