#pragma once
#include <vector>
#include <optional>
#include <cstdint>
#include <string>
#include "hash_params.h"



// Cuckoo hash table
class CuckooHashTable {
public:
    CuckooHashTable() = default;
    // hash_indices: indices of hash functions to use, all_hashes: all available hash functions
    CuckooHashTable(size_t num_bins, size_t threshold,
        const std::vector<size_t>& hash_indices,
        const std::vector<HashParams>& all_hashes);

    // Insert a single value
    bool insert(uint32_t value);

    // Bulk insert, returns the number of elements that failed to insert
    size_t insert_all(const std::vector<uint32_t>& elements);

    // Return the current table (vector of bins)
    const std::vector<std::optional<uint32_t>>& get_table() const;

    // Return the names of the used hash functions
    std::vector<std::string> get_used_hash_names() const;

private:
    std::vector<HashParams> hash_functions_;
    std::vector<std::string> hash_names_;
    size_t num_bins_;
    size_t num_hash_functions_;
    size_t threshold_;
    std::vector<std::optional<uint32_t>> table_;

    uint64_t universal_hash(const HashParams& p, uint32_t value) const;
};

// Generate a fixed set of hash functions (default: 10)
std::vector<HashParams> generate_hash_functions(size_t num_bins, size_t count);
std::vector<HashParams> generate_fixed_hash_functions(size_t num_bins, size_t count);
// Generate all nCk combinations
std::vector<std::vector<size_t>> get_combinations(size_t n, size_t k);
