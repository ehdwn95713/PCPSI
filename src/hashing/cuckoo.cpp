#include "cuckoo.h"
#include <random>
#include <algorithm>
#include <cmath>
#include <set>

// generate prime
static uint64_t next_prime(uint64_t n) {
    auto is_prime = [](uint64_t x) {
        if (x < 2) return false;
        for (uint64_t i = 2; i <= std::sqrt(x); ++i)
            if (x % i == 0) return false;
        return true;
    };
    while (!is_prime(n)) ++n;
    return n;
}

std::vector<HashParams> generate_hash_functions(size_t num_bins, size_t count) {
    std::vector<HashParams> hash_functions;
    std::set<uint64_t> used_primes;
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist_c(1, num_bins * 100);
    std::uniform_int_distribution<uint64_t> dist_seed(1, UINT32_MAX);

    for (size_t i = 0; i < count; ++i) {
        uint64_t base = num_bins * num_bins + dist_c(gen);
        uint64_t prime = next_prime(base);
        while (used_primes.count(prime)) prime = next_prime(prime + 1);
        used_primes.insert(prime);

        uint64_t seed = dist_seed(gen);
        uint64_t c0 = dist_c(gen);
        uint64_t c1 = next_prime(dist_c(gen));
        uint64_t c2 = next_prime(dist_c(gen));
        uint64_t c3 = dist_c(gen);

        hash_functions.push_back({c0, c1, c2, c3, prime, seed, num_bins, "hash_" + std::to_string(i + 1)});
    }
    return hash_functions;
}

std::vector<HashParams> generate_fixed_hash_functions(size_t num_bins, size_t count) {
    std::vector<HashParams> hash_functions;
    // 예시: 그냥 count만큼, 값들을 패턴화해서 고정 생성
    for (size_t i = 0; i < count; ++i) {
        uint64_t prime = next_prime(num_bins * num_bins + 100 + i); // i별로 증가
        uint64_t seed  = 12345 + i;           // 고정값 + index
        uint64_t c0    = 1000 + i;
        uint64_t c1    = next_prime(2000 + i);
        uint64_t c2    = next_prime(3000 + i);
        uint64_t c3    = 4000 + i;
        hash_functions.push_back({
            c0, c1, c2, c3, prime, seed, num_bins, "fixed_hash_" + std::to_string(i+1)
        });
    }
    return hash_functions;
}


std::vector<std::vector<size_t>> get_combinations(size_t n, size_t k) {
    std::vector<std::vector<size_t>> result;
    std::vector<bool> select(n, false);
    std::fill(select.begin(), select.begin() + k, true);
    do {
        std::vector<size_t> comb;
        for (size_t i = 0; i < n; ++i)
            if (select[i]) comb.push_back(i);
        result.push_back(comb);
    } while (std::prev_permutation(select.begin(), select.end()));
    return result;
}

CuckooHashTable::CuckooHashTable(size_t num_bins, size_t threshold,
        const std::vector<size_t>& hash_indices,
        const std::vector<HashParams>& all_hashes)
    : num_bins_(num_bins), threshold_(threshold),
      num_hash_functions_(hash_indices.size()), table_(num_bins, std::nullopt)
{
    for (size_t idx : hash_indices) {
        hash_functions_.push_back(all_hashes[idx]);
        hash_names_.push_back(all_hashes[idx].name);
    }
}

uint64_t CuckooHashTable::universal_hash(const HashParams& p, uint32_t value) const {
    uint64_t x = value ^ p.seed;
    uint64_t t = (p.c3 * x + p.c2) % p.prime;
    t = (t * p.c1 + p.c0) % p.mod;
    return t;
}

bool CuckooHashTable::insert(uint32_t value) {
    uint32_t cur = value;
    size_t which_fn = 0;
    for (size_t reloc = 0; reloc < threshold_; ++reloc) {
        size_t bin = universal_hash(hash_functions_[which_fn], cur);
        if (!table_[bin].has_value()) {
            table_[bin] = cur;
            return true;
        }
        std::swap(cur, table_[bin].value());
        which_fn = (which_fn + 1) % num_hash_functions_;
    }
    return false; // insertion failed
}

size_t CuckooHashTable::insert_all(const std::vector<uint32_t>& elements) {
    size_t fail_count = 0;
    for (auto v : elements) {
        if (!insert(v)) ++fail_count;
    }
    return fail_count;
}

const std::vector<std::optional<uint32_t>>& CuckooHashTable::get_table() const {
    return table_;
}

std::vector<std::string> CuckooHashTable::get_used_hash_names() const {
    return hash_names_;
}
