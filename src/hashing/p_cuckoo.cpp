#include "p_cuckoo.h"
#include <algorithm>
#include <iostream>

PermCuckooTable::PermCuckooTable(
    size_t num_bins,
    size_t threshold,
    size_t r,
    const std::vector<size_t>& hash_indices,
    const std::vector<HashParams>& all_hashes
)
    : num_bins_(num_bins), threshold_(threshold),
      num_hash_functions_(hash_indices.size()), r_(r), mask_r_((1U << r) - 1),
      table_(num_bins, std::nullopt)
{
    for (size_t idx : hash_indices) {
        hash_functions_.push_back(all_hashes[idx]);
        hash_names_.push_back(all_hashes[idx].name);
    }
}

uint64_t PermCuckooTable::universal_hash(const HashParams& p, uint32_t value) const {
    uint64_t x = value ^ p.seed;
    uint64_t t = (p.c3 * x + p.c2) % p.prime;
    t = (t * p.c1 + p.c0) % p.mod;
    return t;
}

bool PermCuckooTable::insert(uint32_t value) {
    uint32_t x_l = value >> r_;
    uint32_t x_r = value & mask_r_;
    uint32_t cur_l = x_l;
    uint32_t cur_r = x_r;
    size_t which_fn = 0;

    for (size_t reloc = 0; reloc < threshold_; ++reloc) {
        size_t bin = cur_l ^ universal_hash(hash_functions_[which_fn], cur_r);
        bin %= num_bins_;
        if (!table_[bin].has_value()) {
            table_[bin] = TableEntry{cur_r, which_fn};
            return true;
        }
        // displacement: swap cur_r/hash_idx와 기존 slot
        TableEntry prev = table_[bin].value();
        table_[bin] = TableEntry{cur_r, which_fn};
        cur_r = prev.x_r;
        // which_fn displacement: 실제 이전 hash idx를 이어감
        cur_l = bin ^ universal_hash(hash_functions_[prev.hash_idx], cur_r);
        which_fn = (which_fn + 1) % num_hash_functions_;
    }
    return false; // insertion failed
}

size_t PermCuckooTable::insert_all(const std::vector<uint32_t>& elements) {
    size_t fail_count = 0;
    for (auto v : elements) {
        if (!insert(v)) ++fail_count;
    }
    return fail_count;
}

const std::vector<std::optional<TableEntry>>& PermCuckooTable::get_table() const {
    return table_;
}

std::vector<std::string> PermCuckooTable::get_used_hash_names() const {
    return hash_names_;
}
#include "p_cuckoo.h"

// PermCuckooTable에서 hash_idx별로 테이블 분리
std::vector<std::vector<std::optional<uint32_t>>>
split_per_hash_tables(const PermCuckooTable& cuckoo_table, size_t num_hash)
{
    const auto& big_table = cuckoo_table.get_table();
    size_t num_bins = big_table.size();

    std::vector<std::vector<std::optional<uint32_t>>> hash_tables(
        num_hash, std::vector<std::optional<uint32_t>>(num_bins, std::nullopt));

    for (size_t bin = 0; bin < num_bins; ++bin) {
        if (big_table[bin].has_value()) {
            const TableEntry& entry = big_table[bin].value();
            size_t hash_idx = entry.hash_idx;
            uint32_t x_r = entry.x_r;
            // 해당 hash_idx의 테이블에만 기록
            hash_tables[hash_idx][bin] = x_r;
        }
    }
    return hash_tables;
}
#include "p_cuckoo.h"

// ...기존 코드...

PermCuckooBuildResult build_successful_p_cuckoo_table(
    size_t bins,
    size_t threshold,
    size_t r,
    const std::vector<std::vector<size_t>>& combs,
    const std::vector<HashParams>& all_hashes,
    const std::vector<uint32_t>& client_elems
) {
    for (const auto& indices : combs) {
        PermCuckooTable table(bins, threshold, r, indices, all_hashes);
        if (table.insert_all(client_elems) == 0) {
            // 성공한 경우
            std::cout << "Permutation Cuckoo hashing succeeded! Used hash functions: ";
            for (const auto& name : table.get_used_hash_names())
                std::cout << name << " ";
            std::cout << std::endl;
            return {table, indices};
        }
    }
    std::cerr << "No combination of hash functions succeeded for PermCuckoo.\n";
    exit(1); // 실패 시 프로그램 종료 (혹은 적절한 예외 처리)
}


// #include "p_cuckoo.h"
// #include <algorithm>

// PermCuckooTable::PermCuckooTable(
//     size_t num_bins,
//     size_t threshold,
//     size_t r,
//     const std::vector<size_t>& hash_indices,
//     const std::vector<HashParams>& all_hashes
// )
//     : num_bins_(num_bins), threshold_(threshold),
//       num_hash_functions_(hash_indices.size()), r_(r), mask_r_((1U << r) - 1),
//       table_(num_bins, std::nullopt)
// {
//     for (size_t idx : hash_indices) {
//         hash_functions_.push_back(all_hashes[idx]);
//         hash_names_.push_back(all_hashes[idx].name);
//     }
// }

// uint64_t PermCuckooTable::universal_hash(const HashParams& p, uint32_t value) const {
//     uint64_t x = value ^ p.seed;
//     uint64_t t = (p.c3 * x + p.c2) % p.prime;
//     t = (t * p.c1 + p.c0) % p.mod;
//     return t;
// }

// bool PermCuckooTable::insert(uint32_t value) {
//     uint32_t x_l = value >> r_;
//     uint32_t x_r = value & mask_r_;
//     uint32_t cur_l = x_l;
//     uint32_t cur_r = x_r;
//     size_t which_fn = 0;

//     for (size_t reloc = 0; reloc < threshold_; ++reloc) {
//         size_t bin = cur_l ^ universal_hash(hash_functions_[which_fn], cur_r);
//         bin %= num_bins_;
//         if (!table_[bin].has_value()) {
//             table_[bin] = cur_r;
//             return true;
//         }
//         std::swap(cur_r, table_[bin].value());
//         // displacement 시 cur_l 업데이트
//         cur_l = bin ^ universal_hash(hash_functions_[which_fn], cur_r);
//         which_fn = (which_fn + 1) % num_hash_functions_;
//     }
//     return false; // insertion failed
// }

// size_t PermCuckooTable::insert_all(const std::vector<uint32_t>& elements) {
//     size_t fail_count = 0;
//     for (auto v : elements) {
//         if (!insert(v)) ++fail_count;
//     }
//     return fail_count;
// }

// const std::vector<std::optional<uint32_t>>& PermCuckooTable::get_table() const {
//     return table_;
// }

// std::vector<std::string> PermCuckooTable::get_used_hash_names() const {
//     return hash_names_;
// }
