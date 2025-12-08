#include "seal_util/examples.h"
#include "seal_util/batching.h"
#include "data/data_generator.h"
#include "data/data_reader.h"
#include "hashing/cuckoo.h"
#include "hashing/simple.h"
#include "hashing/p_cuckoo.h"
#include "network/wire.h"
#include "network/psi_wire.h"
#include <filesystem>
#include <iostream>
#include "seal/seal.h"

using namespace std;
using namespace seal;

int main(int argc, char** argv) {
    // 1. 클라이언트 연결을 기다리는 Wire (서버 모드)
    int port = 9000;
    if (argc > 1) {
        port = std::stoi(argv[1]);
    }
    std::cout << "Server listening on port " << port << "...\n";
    Wire wire(port);   // 여기서 listen + accept 한번 수행됨
    std::cout << "Client connected.\n";

    // ------------------ server data 생성/로드 ------------------
    size_t server_size = 1 << 20;
    std::string server_path = "data/data_file/server_data.txt";

    if (!std::filesystem::exists(server_path)) {
        create_server_data(server_size);
        std::cout << "Server data files created.\n";
    } else {
        std::cout << "Server data files already exist. Skipping generation.\n";
    }
    auto server_elems = read_uint32_file(server_path);
    std::cout << "Loaded " << server_elems.size() << " server elements\n";

    // ------------------ 공통 파라미터 ------------------
    int    log_poly_mod = 12;
    size_t log_bins     = log_poly_mod;
    size_t bins         = 1 << log_bins;
    size_t hash_count   = 3;
    size_t threshold    = 3000;
    size_t r            = 22 - log_bins; // 나중에 server_tables 만들 때도 사용
    const uint32_t SHIFT = 14; // 2-dimensional batching segment

    // ------------------ 서버: hash 20개 생성 ------------------
    auto all_hashes = generate_fixed_hash_functions(bins, 20);

    // ---- 여기서 클라이언트에게 hash 파라미터 전체 전송 ----
    send_hash_params(wire, all_hashes);
    std::cout << "Sent " << all_hashes.size() << " hash functions to client.\n";

    // (뒤에서 parms/pk/ chosen_hashes, query ct 등을 받는 코드는
    //  다음 단계에서 이어서 넣으면 됨)
    // ---- 여기서부터 클라이언트가 보낸 setup 정보 수신 ----

    // 1) parms 수신 (context 없이)
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    recv_seal_parms(wire, parms);

    // 2) context 생성
    seal::SEALContext context(parms);

    // 3) public key 수신 (context 필요)
    seal::PublicKey public_key;
    recv_seal_obj(wire, public_key, context);

    // 4) chosen_hashes 수신
    std::vector<HashParams> chosen_hashes = recv_hash_params(wire);

    // 5) 이후 batch_encoder, evaluator 등 생성
    seal::BatchEncoder batch_encoder(context);
    seal::Evaluator   evaluator(context);

    // 이제 server_elems, chosen_hashes, batch_encoder, evaluator 를 써서
    // permutation simple table 만들고, 나중에 ct_all 받아서 HE 연산 하면 됨.

    // --- permutation-based simple table generation (server only) ---
    auto start_gen_sim = std::chrono::high_resolution_clock::now();
    auto server_tables = build_permsimple_tables_for_hashes(
        bins,         // client/서버가 공유하는 bin 수
        r,            // 동일한 r
        chosen_hashes,
        server_elems  // 서버의 실제 집합
    );
    auto end_gen_sim = std::chrono::high_resolution_clock::now();
    auto us_gen_sim = std::chrono::duration_cast<std::chrono::microseconds>(
                        end_gen_sim - start_gen_sim
                    ).count();

    std::cout << "Permutation simple tables generated in "
            << us_gen_sim << " us" << std::endl;

    // --- 클라이언트 쿼리 ciphertext 수신 ---
    wire.reset_stats();
    seal::Ciphertext ct_all;
    recv_seal_obj(wire, ct_all, context);
    std::cout << "Received ct_all from client\n";
    
    // server encoding
    std::vector<std::vector<seal::Plaintext>> server_plaintexts_set;
    size_t num_hash = chosen_hashes.size();                
    for (size_t h = 0; h < num_hash; ++h) {

        const auto& simple_table_vec = server_tables[h].get_table();
        uint32_t r_val = 1u << r;
        std::vector<std::vector<uint32_t>> shifted_simple_table_vec = simple_table_vec;

        // STEP 1: 2^r - x_R (shift)
        for (auto& bin_vec : shifted_simple_table_vec) {
            for (auto& elem : bin_vec) {
                elem = r_val - elem;
            }
        }

        // STEP 2: (vL | (vR << SHIFT)) 으로 2D packing
        for (auto& bin_vec : shifted_simple_table_vec) {
            std::vector<uint32_t> merged;
            merged.reserve((bin_vec.size() + 1) / 2);

            for (size_t j = 0; j < bin_vec.size(); j += 2) {
                uint32_t vL = bin_vec[j];
                if (j + 1 < bin_vec.size()) {
                    uint32_t vR = bin_vec[j + 1];
                    merged.push_back(vL | (vR << SHIFT));
                } else {
                    merged.push_back(vL);
                }
            }
            bin_vec.swap(merged);
        }

        // STEP 3: pad
        uint32_t padding = 0;
        auto padded = pad_simple_table_vec(shifted_simple_table_vec, padding);

        // STEP 4: encode
        auto server_plaintexts = encode_simple_table(
            padded, batch_encoder, padding
        );

        server_plaintexts_set.push_back(std::move(server_plaintexts));
    }
    
    
    // ====================== 서버: 난수 plaintext 생성 ======================
    std::vector<uint64_t> rand_vec(batch_encoder.slot_count());
    uint32_t t = parms.plain_modulus().value();
    std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint32_t> dist(1, t - 1);

    // 예전처럼 패턴으로 해도 되고, 완전 랜덤으로 해도 됨.
    // 여기서는 원래 코드 유지:
    for (size_t i = 0; i < rand_vec.size(); ++i) {
        rand_vec[i] = (i % 2) * 2 + 1;   // always odd
    }

    seal::Plaintext rand_plain;
    batch_encoder.encode(rand_vec, rand_plain);

    long long total_us_comp = 0;

    // ====================== 서버: compare_results 계산 + 전송 ======================
    for (size_t h = 0; h < num_hash; ++h) {
        std::vector<seal::Ciphertext> compare_results;

        auto start_comp = std::chrono::high_resolution_clock::now();

        // ct_all + server_plaintexts[h][i], 그리고 rand_plain로 곱하기
        for (const auto& pt : server_plaintexts_set[h]) {
            seal::Ciphertext diff;
            evaluator.add_plain(ct_all, pt, diff);
            evaluator.multiply_plain_inplace(diff, rand_plain);
            compare_results.push_back(std::move(diff));
        }

        auto end_comp = std::chrono::high_resolution_clock::now();
        auto us_comp = std::chrono::duration_cast<std::chrono::microseconds>(
                        end_comp - start_comp
                    ).count();
        double ms_comp = us_comp / 1000.0;
        total_us_comp += us_comp;

        // ---- 결과를 클라이언트에 전송 ----
        // 1) 이 hash에 대한 ciphertext 개수 먼저 전송
        send_u64(wire, static_cast<std::uint64_t>(compare_results.size()));

        // 2) 각 ciphertext 전송
        for (const auto& ct : compare_results) {
            send_seal_obj(wire, ct);
        }

        std::cout << "[server] hash " << h
                << " compare_results = " << compare_results.size()
                << ", comp time = " << ms_comp << " ms\n";
    }
    
    double ms_gen_sim = us_gen_sim / 1000.0;

    std::cout << "\n[server] SIMPLE table time = "
          << ms_gen_sim
          << std::endl;

    double total_ms_comp = total_us_comp / 1000.0;
    std::cout << "[server] TOTAL compare time = "
          << total_ms_comp << "\n";

    double mb_s2c = wire.bytes_sent() / (1024.0 * 1024.0);
    double mb_c2s = wire.bytes_recv() / (1024.0 * 1024.0);

    double ms_send = wire.send_time_us() / 1000.0;
    double ms_recv = wire.recv_time_us() / 1000.0;
    double ms_comm_total = ms_send + ms_recv;

    std::cout << "\n[server] bytes server->client: "
              << wire.bytes_sent() << " B (" << mb_s2c << " MB)\n";
    std::cout << "[server] bytes client->server: "
              << wire.bytes_recv() << " B (" << mb_c2s << " MB)\n";
    std::cout << "[server] time send: " << ms_send << " ms, "
              << "recv: " << ms_recv << " ms, "
              << "total comm time: " << ms_comm_total << " ms\n";



    return 0;
}
