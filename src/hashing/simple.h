#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include "hash_params.h"
#include "seal/seal.h"

// struct HashParams {
//     uint64_t c0, c1, c2, c3;
//     uint64_t prime;
//     uint64_t seed;
//     uint64_t mod;
//     std::string name;
// };

class SimpleHashTable {
public:
    // bins: number of bins, hash_functions: successful hash function parameters
    SimpleHashTable(size_t bins, const std::vector<HashParams>& hash_functions);

    // Insert one value using all hash functions
    void insert(uint32_t value);

    // Bulk insert for all server elements
    void insert_all(const std::vector<uint32_t>& elements);

    // Access the bins
    const std::vector<std::vector<uint32_t>>& get_table() const;

private:
    std::vector<HashParams> hash_functions_;
    size_t num_bins_;
    std::vector<std::vector<uint32_t>> table_;

    uint64_t universal_hash(const HashParams& p, uint32_t value) const;
};

std::vector<seal::Ciphertext> batch_encrypt_simple_table(
    const std::vector<std::vector<uint32_t>>& simple_table,
    seal::Encryptor& encryptor,
    seal::BatchEncoder& batch_encoder,
    uint32_t placeholder = 0  // empty slot to zero
);

std::vector<seal::Plaintext> encode_simple_table(
    const std::vector<std::vector<uint32_t>>& simple_table,
    seal::BatchEncoder& batch_encoder,
    uint32_t placeholder = 0
);

std::vector<std::vector<uint32_t>> pad_simple_table_vec(
    const std::vector<std::vector<uint32_t>>& table,
    uint32_t placeholder = 0
);

// Permutation-based simple hash table
class PermSimpleHashTable {
public:
    PermSimpleHashTable(size_t bins, size_t r, const std::vector<HashParams>& hash_functions);

    void insert(uint32_t value);
    void insert_all(const std::vector<uint32_t>& elements);

    // x_R만 저장된 테이블
    const std::vector<std::vector<uint32_t>>& get_table() const;

private:
    std::vector<HashParams> hash_functions_;
    size_t num_bins_;
    size_t r_;
    uint32_t mask_r_;
    std::vector<std::vector<uint32_t>> table_;

    uint64_t universal_hash(const HashParams& p, uint32_t value) const;
};

std::vector<SimpleHashTable>
build_simple_tables_for_hashes(
    size_t bins,
    const std::vector<HashParams>& chosen_hashes,
    const std::vector<uint32_t>& server_elems
);

// PermSimpleHashTable 기반 build 함수 선언
std::vector<PermSimpleHashTable>
build_permsimple_tables_for_hashes(
    size_t bins,
    size_t r,
    const std::vector<HashParams>& chosen_hashes,
    const std::vector<uint32_t>& server_elems
);
