#include "simple.h"
#include <algorithm>

SimpleHashTable::SimpleHashTable(size_t bins, const std::vector<HashParams>& hash_functions)
    : hash_functions_(hash_functions), num_bins_(bins), table_(bins) {}

uint64_t SimpleHashTable::universal_hash(const HashParams& p, uint32_t value) const {
    uint64_t x = value ^ p.seed;
    uint64_t t = (p.c3 * x + p.c2) % p.prime;
    t = (t * p.c1 + p.c0) % p.mod;
    return t;
}

void SimpleHashTable::insert(uint32_t value) {
    for (const auto& hash_p : hash_functions_) {
        size_t bin = universal_hash(hash_p, value);
        table_[bin].push_back(value);
    }
}

void SimpleHashTable::insert_all(const std::vector<uint32_t>& elements) {
    for (auto v : elements) {
        insert(v);
    }
}

const std::vector<std::vector<uint32_t>>& SimpleHashTable::get_table() const {
    return table_;
}

std::vector<seal::Ciphertext> batch_encrypt_simple_table(
    const std::vector<std::vector<uint32_t>>& simple_table,
    seal::Encryptor& encryptor,
    seal::BatchEncoder& batch_encoder,
    uint32_t placeholder)
{
    size_t bins = simple_table.size();
    size_t max_load = 0;
    for (const auto& bin : simple_table)
        max_load = std::max(max_load, bin.size());

    std::vector<seal::Ciphertext> result;
    for (size_t load = 0; load < max_load; ++load) {
        // bins 개의 slot에 각 load 번째 값(없으면 placeholder) 배치
        std::vector<uint64_t> slots(bins, placeholder);
        for (size_t bin = 0; bin < bins; ++bin) {
            if (simple_table[bin].size() > load)
                slots[bin] = simple_table[bin][load];
        }
        seal::Plaintext plain;
        batch_encoder.encode(slots, plain);
        seal::Ciphertext ct;
        encryptor.encrypt(plain, ct);
        result.push_back(std::move(ct));
    }
    return result;
}

std::vector<seal::Plaintext> encode_simple_table(
    const std::vector<std::vector<uint32_t>>& simple_table,
    seal::BatchEncoder& batch_encoder,
    uint32_t placeholder)
{
    size_t bins = simple_table.size();
    size_t max_load = 0;
    for (const auto& bin : simple_table)
        max_load = std::max(max_load, bin.size());

    std::vector<seal::Plaintext> result;
    for (size_t load = 0; load < max_load; ++load) {
        std::vector<uint64_t> slots(bins, placeholder);
        for (size_t bin = 0; bin < bins; ++bin) {
            if (simple_table[bin].size() > load)
                slots[bin] = simple_table[bin][load];
        }
        seal::Plaintext plain;
        batch_encoder.encode(slots, plain);
        result.push_back(std::move(plain));
    }
    return result;
}

std::vector<std::vector<uint32_t>> pad_simple_table_vec(
    const std::vector<std::vector<uint32_t>>& table,
    uint32_t placeholder
) {
    // 먼저 max_load 구하기
    size_t max_load = 0;
    for (const auto& bin : table) {
        if (bin.size() > max_load) max_load = bin.size();
    }

    // 새 테이블 만들기
    std::vector<std::vector<uint32_t>> padded_table;
    padded_table.reserve(table.size());

    for (const auto& bin : table) {
        std::vector<uint32_t> padded_bin = bin;
        while (padded_bin.size() < max_load) {
            padded_bin.push_back(placeholder);
        }
        padded_table.push_back(std::move(padded_bin));
    }

    return padded_table;
}

PermSimpleHashTable::PermSimpleHashTable(size_t bins, size_t r, const std::vector<HashParams>& hash_functions)
    : hash_functions_(hash_functions), num_bins_(bins), r_(r), mask_r_((1U << r) - 1), table_(bins)
{}

uint64_t PermSimpleHashTable::universal_hash(const HashParams& p, uint32_t value) const {
    uint64_t x = value ^ p.seed;
    uint64_t t = (p.c3 * x + p.c2) % p.prime;
    t = (t * p.c1 + p.c0) % p.mod;
    return t;
}

void PermSimpleHashTable::insert(uint32_t value) {
    uint32_t x_l = value >> r_;
    uint32_t x_r = value & mask_r_;
    for (const auto& hash_p : hash_functions_) {
        size_t bin = x_l ^ universal_hash(hash_p, x_r);
        bin %= num_bins_; // 안전하게 mod
        table_[bin].push_back(x_r); // x_R만 저장
    }
}

void PermSimpleHashTable::insert_all(const std::vector<uint32_t>& elements) {
    for (auto v : elements)
        insert(v);
}

const std::vector<std::vector<uint32_t>>& PermSimpleHashTable::get_table() const {
    return table_;
}

std::vector<SimpleHashTable>
build_simple_tables_for_hashes(
    size_t bins,
    const std::vector<HashParams>& chosen_hashes,
    const std::vector<uint32_t>& server_elems
) {
    std::vector<SimpleHashTable> tables;
    for (const auto& hash : chosen_hashes) {
        std::vector<HashParams> one_hash = {hash};
        SimpleHashTable table(bins, one_hash);
        table.insert_all(server_elems);
        tables.push_back(std::move(table));
    }
    return tables;
}

std::vector<PermSimpleHashTable>
build_permsimple_tables_for_hashes(
    size_t bins,
    size_t r,
    const std::vector<HashParams>& chosen_hashes,
    const std::vector<uint32_t>& server_elems
) {
    std::vector<PermSimpleHashTable> tables;
    for (const auto& hash : chosen_hashes) {
        std::vector<HashParams> one_hash = {hash};
        PermSimpleHashTable table(bins, r, one_hash);
        table.insert_all(server_elems);
        tables.push_back(std::move(table));
    }
    return tables;
}
