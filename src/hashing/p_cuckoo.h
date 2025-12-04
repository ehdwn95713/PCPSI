#pragma once
#include <vector>
#include <optional>
#include <string>
#include <cstdint>
#include "hash_params.h"

// 각 slot에 저장할 entry: x_R와 hash 함수 인덱스
struct TableEntry {
    uint32_t x_r;
    size_t hash_idx;
};

// Permutation-based Cuckoo Hash Table
class PermCuckooTable {
public:
    PermCuckooTable(
        size_t num_bins,
        size_t threshold,
        size_t r,
        const std::vector<size_t>& hash_indices,
        const std::vector<HashParams>& all_hashes
    );

    // 삽입 (x를 x_L, x_R로 분리해서 넣음)
    bool insert(uint32_t value);

    // 전체 삽입
    size_t insert_all(const std::vector<uint32_t>& elements);

    // 테이블 getter (x_R와 hash_idx 저장)
    const std::vector<std::optional<TableEntry>>& get_table() const;

    std::vector<std::string> get_used_hash_names() const;

    uint64_t universal_hash(const HashParams& p, uint32_t value) const;

private:
    size_t num_bins_;
    size_t threshold_;
    size_t num_hash_functions_;
    size_t r_; // x를 분할할 하위 비트 개수
    uint32_t mask_r_; // x_R 추출용 마스크

    std::vector<HashParams> hash_functions_;
    std::vector<std::string> hash_names_;
    std::vector<std::optional<TableEntry>> table_; // 변경: TableEntry로 저장
};

// (추가!) hash_idx별 테이블 분리 함수
std::vector<std::vector<std::optional<uint32_t>>> 
split_per_hash_tables(const PermCuckooTable& cuckoo_table, size_t num_hash);

// 성공한 permutation-based cuckoo 테이블과 chosen_indices를 리턴
struct PermCuckooBuildResult {
    PermCuckooTable table;
    std::vector<size_t> chosen_indices;
};

std::optional<PermCuckooBuildResult>
build_successful_p_cuckoo_table(
    size_t bins,
    size_t threshold,
    size_t r,
    const std::vector<std::vector<size_t>>& combs,
    const std::vector<HashParams>& all_hashes,
    const std::vector<uint32_t>& client_elems
);






// #pragma once
// #include <vector>
// #include <optional>
// #include <string>
// #include <cstdint>
// #include "hash_params.h"



// // Permutation-based Cuckoo Hash Table
// class PermCuckooTable {
// public:
//     PermCuckooTable(
//         size_t num_bins,
//         size_t threshold,
//         size_t r,
//         const std::vector<size_t>& hash_indices,
//         const std::vector<HashParams>& all_hashes
//     );

//     // 삽입 (x를 x_L, x_R로 분리해서 넣음)
//     bool insert(uint32_t value);

//     // 전체 삽입
//     size_t insert_all(const std::vector<uint32_t>& elements);

//     // 테이블 getter (x_R만 저장)
//     const std::vector<std::optional<uint32_t>>& get_table() const;

//     // 사용한 해시 함수 이름들
//     std::vector<std::string> get_used_hash_names() const;

//     // universal hash (기존 방식)
//     uint64_t universal_hash(const HashParams& p, uint32_t value) const;

// private:
//     size_t num_bins_;
//     size_t threshold_;
//     size_t num_hash_functions_;
//     size_t r_; // x를 분할할 하위 비트 개수
//     uint32_t mask_r_; // x_R 추출용 마스크

//     std::vector<HashParams> hash_functions_;
//     std::vector<std::string> hash_names_;
//     std::vector<std::optional<uint32_t>> table_;
// };
