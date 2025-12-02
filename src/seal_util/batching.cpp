#include "batching.h"


Ciphertext batch_encrypt_cuckoo_bins_range(
    const vector<uint32_t> &cuckoo_bins, // 전체 bin
    size_t start_idx,
    size_t end_idx, // [start_idx, end_idx] 구간만 batching
    Encryptor &encryptor,
    BatchEncoder &batch_encoder)
{   
    size_t slot_count = batch_encoder.slot_count(); // 보통 4096
    size_t range_size = end_idx - start_idx + 1;
    if (end_idx >= cuckoo_bins.size() || start_idx > end_idx)
        throw invalid_argument("Invalid index range!");

    if (range_size > slot_count)
        throw invalid_argument("Range size exceeds slot count!");
    
    // (1) slot_count 크기의 vector 생성 (0으로 초기화)
    vector<uint64_t> slots(slot_count, 0ULL);
    
    // (2) 구간만 복사 (맨 앞에서부터 range_size만큼)
    for (size_t i = 0; i < range_size; ++i)
        slots[i] = static_cast<uint64_t>(cuckoo_bins[start_idx + i]);

    // (3) Batch encode & encrypt
    Plaintext plain;
    batch_encoder.encode(slots, plain);

    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    return encrypted;
}