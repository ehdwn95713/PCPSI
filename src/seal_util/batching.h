#pragma once

#include "seal/seal.h"
#include <vector>
#include <cstdint>

using namespace seal;
using namespace std;

Ciphertext batch_encrypt_cuckoo_bins_range(
    const vector<uint32_t> &cuckoo_bins, // 전체 bin
    size_t start_idx,
    size_t end_idx, // [start_idx, end_idx] 구간만 batching
    Encryptor &encryptor,
    BatchEncoder &batch_encoder);

