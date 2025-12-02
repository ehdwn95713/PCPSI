#include "data_generator.h"
#include <unordered_set>
#include <random>
#include <fstream>
#include <iostream>
#include <filesystem>

constexpr uint32_t MIN_VALUE = 0;
constexpr uint32_t MAX_VALUE = (1<<22) -1 ; // 22bit value

void generate_unique_randoms(const std::string& filepath, size_t count) {
    std::unordered_set<uint32_t> numbers;
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<uint32_t> dist(MIN_VALUE, MAX_VALUE);

    while (numbers.size() < count) {
        uint32_t value = dist(rng);
        numbers.insert(value);
    }

    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "Failed to open file: " << filepath << std::endl;
        exit(1);
    }
    for (const auto& num : numbers) {
        ofs << num << "\n";
    }
    ofs.close();
    std::cout << filepath << " generated (" << count << " entries)" << std::endl;
}


void create_client_data(size_t client_size) {
    std::filesystem::create_directories("data/data_file");
    generate_unique_randoms("data/data_file/client_data.txt", client_size);
}

void create_server_data(size_t server_size) {
    std::filesystem::create_directories("data/data_file");
    generate_unique_randoms("data/data_file/server_data.txt", server_size);
}