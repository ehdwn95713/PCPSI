// client.cpp
#include "seal_util/examples.h"
#include "seal_util/batching.h"
#include "data/data_generator.h"
#include "data/data_reader.h"
#include "hashing/cuckoo.h"
#include "hashing/simple.h"
#include "hashing/p_cuckoo.h"
#include "network/wire.h"        // 나중에 recv 구현용
#include <filesystem>
#include <chrono>
#include <iostream>
#include "network/psi_wire.h"
#include "seal/seal.h"

using namespace std;
using namespace seal;
using namespace std::chrono;

int main(int argc, char** argv) {

    std::string server_host = "127.0.0.1";
    int server_port = 9000;
    if (argc > 1) server_host = argv[1];
    if (argc > 2) server_port = std::stoi(argv[2]);

    Wire wire(server_host, server_port);   // 클라이언트 모드로 connect
    std::cout << "Connected to " << server_host << ":" << server_port << "\n";

    // ------------- BFV parameter setting (client side) -------------
    EncryptionParameters parms(scheme_type::bfv);
    int    log_poly_mod       = 12;
    size_t poly_modulus_degree = 1 << log_poly_mod;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    

    auto plain_mod = PlainModulus::Batching(poly_modulus_degree, 27);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, {60, 49}));  // 109-bit Q
    parms.set_plain_modulus(plain_mod);

    cout << "Plainmodulus: " << plain_mod.value() << endl;
    SEALContext context(parms);

    // key generation
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor  encryptor(context, public_key);
    Decryptor  decryptor(context, secret_key);
    Evaluator  evaluator(context);
    BatchEncoder batch_encoder(context);

    // ------------- client data 생성/로드 ----------------
    size_t client_size = 1 << 10;
    std::string client_path = "data/data_file/client_data.txt";

    if (!std::filesystem::exists(client_path)) {
        create_client_data(client_size);
        std::cout << "Client data files created.\n";
    } else {
        std::cout << "Client data files already exist. Skipping generation.\n";
    }
    auto client_elems = read_uint32_file(client_path);
    std::cout << "Loaded " << client_elems.size() << " client elements\n";

    // ------------- 공통 파라미터 ----------------
    int    log_bins   = log_poly_mod;
    size_t bins       = 1 << log_bins;
    size_t hash_count = 3;
    size_t threshold  = 3000;
    size_t r          = 22 - log_bins;
    const uint32_t SHIFT = 14; // 2-dimensional batching segment
    
    // 각 k(=1,2,3)에 대한 load factor threshold L_k
    // index 0은 사용 안 함
    std::array<double, 4> load_factor_thr = {0.0, 0.1, 0.22, 0.73};
    // // ------------- 서버에서 all_hashes 받기 ----------------
    // std::vector<HashParams> all_hashes;

    // // 예전: all_hashes = generate_fixed_hash_functions(bins, 20); // 임시

    // all_hashes = recv_hash_params(wire);   // 서버가 보낸 20개 hash 파라미터 수신
    // std::cout << "Received " << all_hashes.size()
    //           << " hash functions from server.\n";


    // // ------------- permutation-based cuckoo table 구축 -------------
    // auto combs = get_combinations(20, hash_count);

    // auto start_gen_cuc = high_resolution_clock::now();
    // auto build_result  = build_successful_p_cuckoo_table(
    //     bins, threshold, r, combs, all_hashes, client_elems);

    // PermCuckooTable& p_cuckoo_table = build_result.table;
    // auto end_gen_cuc = high_resolution_clock::now();
    // auto us_gen_cuc  = duration_cast<microseconds>(end_gen_cuc - start_gen_cuc).count();

    // std::vector<size_t>& chosen_indices = build_result.chosen_indices;

    // std::cout << "Cuckoo table generated in " << us_gen_cuc << " us\n";
    // std::cout << "Chosen hash indices: ";
    // for (auto idx : chosen_indices) std::cout << idx << " ";
    // std::cout << std::endl;

    //     // 1) chosen_hashes 추출
    // std::vector<HashParams> chosen_hashes;
    // for (auto idx : chosen_indices)
    //     chosen_hashes.push_back(all_hashes[idx]);

    // // 2) 서버에 setup 정보 전송 (BFV parms, PK, chosen_hashes)
    // send_seal_obj(wire, parms);          // EncryptionParameters
    // send_seal_obj(wire, public_key);     // PublicKey
    // send_hash_params(wire, chosen_hashes); // vector<HashParams>


    // ------------- 서버에서 all_hashes 받기 ----------------
    std::vector<HashParams> all_hashes;
    all_hashes = recv_hash_params(wire);
    std::cout << "Received " << all_hashes.size()
            << " hash functions from server.\n";

    // ------------- Adaptive selection + permutation-based cuckoo -------------
    double load_factor = static_cast<double>(client_elems.size())
                    / static_cast<double>(bins);

    std::optional<PermCuckooTable> p_cuckoo_table_opt;
    std::vector<size_t> chosen_indices;
    bool found = false;
    size_t used_hash_count = 0;

    auto start_gen_cuc = high_resolution_clock::now();

    for (size_t k_star = 1; k_star <= hash_count; ++k_star)
    {
        double Lk = load_factor_thr[k_star];

        // if |X|/B > L_k* then continue
        if (load_factor > Lk) {
            continue;
        }

        // 이 k_star 에 대해 가능한 hash 조합 생성
        auto combs_k = get_combinations(all_hashes.size(), k_star);

        // Permcuckoo(X, {H_1, ..., H_{k*}}, k*)
        auto build_result_opt = build_successful_p_cuckoo_table(
            bins, threshold, r, combs_k, all_hashes, client_elems);

        // 이 k_star 에선 실패 → 다음 k_star 로
        if (!build_result_opt.has_value()) {
            continue;
        }

        // 여기까지 왔으면 성공한 조합을 찾았다는 뜻
        auto& build_result = *build_result_opt;
        p_cuckoo_table_opt.emplace(std::move(build_result.table));
        chosen_indices = std::move(build_result.chosen_indices);
        used_hash_count = k_star;
        found = true;
        break;
    }

    auto end_gen_cuc = high_resolution_clock::now();
    auto us_gen_cuc  = duration_cast<microseconds>(end_gen_cuc - start_gen_cuc).count();

    if (!found) {
        throw std::runtime_error(
            "Adaptive PermCuckoo failed: no valid k* for given load factor");
    }

    std::cout << "Cuckoo table generated in " << us_gen_cuc << " us\n";
    std::cout << "Used hash count k* = " << used_hash_count << "\n";
    std::cout << "Chosen hash indices: ";
    for (auto idx : chosen_indices) std::cout << idx << " ";
    std::cout << std::endl;

    // 실제 테이블 참조 꺼내서 계속 사용
    PermCuckooTable& p_cuckoo_table = *p_cuckoo_table_opt;

    // 1) chosen_hashes 추출
    std::vector<HashParams> chosen_hashes;
    for (auto idx : chosen_indices)
        chosen_hashes.push_back(all_hashes[idx]);

    // 2) 서버에 setup 정보 전송
    send_seal_obj(wire, parms);
    send_seal_obj(wire, public_key);
    send_hash_params(wire, chosen_hashes);

    // (원래 bytes_* 계산은 네트워크 통계용이었으니
    //  필요하면 여기서 따로 로그만 남기면 되고,
    //  통신 자체에는 영향을 안 줌)

    // --- table extraction by each chosen hash (client only) ---
    size_t num_hash = chosen_indices.size();
    auto per_hash_tables = split_per_hash_tables(p_cuckoo_table, num_hash);
    // per_hash_tables[h][bin] == optional<uint32_t> x_R



    std::vector<std::vector<size_t>> non_placeholder_indices(num_hash); 
    // save real element indices per hash
    for (size_t h = 0; h < num_hash; ++h) {
        for (size_t i = 0; i < per_hash_tables[h].size(); ++i) {
            if (per_hash_tables[h][i].has_value()) {
                non_placeholder_indices[h].push_back(i);
            }
        }
    }


    std::vector<uint32_t> cuckoo_bins_all(bins);

    // p_cuckoo_table.get_table() == vector<optional<TableEntry>>
    const auto& cuckoo_table_all = p_cuckoo_table.get_table();

    for (size_t i = 0; i < bins; ++i) {
        if (cuckoo_table_all[i].has_value()) {
            uint32_t val = cuckoo_table_all[i]->x_r;
            // lower 14bit = val, upper 14bit = val
            cuckoo_bins_all[i] = val | (val << SHIFT);
        } else {
            cuckoo_bins_all[i] = 0; // dummy
        }
    }

    // encryption (client, 단일 ciphertext)
    seal::Ciphertext ct_all;
    long long total_us_enc=0;
    auto start_enc = high_resolution_clock::now();    
    ct_all = batch_encrypt_cuckoo_bins_range(
        cuckoo_bins_all, 0, cuckoo_bins_all.size()-1, encryptor, batch_encoder
    );
    auto end_enc = high_resolution_clock::now();
    auto us_enc = duration_cast<microseconds>(end_enc - start_enc).count();
    total_us_enc+=us_enc;

    // send query
    send_seal_obj(wire, ct_all);


    std::uint64_t total_intersection_count = 0;
    long long total_us_dec   = 0;
    long long total_us_check = 0;

    for (size_t h = 0; h < num_hash; ++h) {
        // ---- 서버로부터 결과 수신 ----
        std::uint64_t num_ct = recv_u64(wire);   // 이 hash에 대한 ciphertext 개수
        std::vector<seal::Ciphertext> compare_results(num_ct);

        for (std::uint64_t i = 0; i < num_ct; ++i) {
            recv_seal_obj(wire, compare_results[i], context);
        }

        int intersection_count = 0;

        // ---- 각 ciphertext를 복호 + 검사 ----
        for (size_t i = 0; i < compare_results.size(); ++i) {
            seal::Plaintext plain;
            std::vector<uint64_t> slots(batch_encoder.slot_count());

            // decrypt
            auto start_dec = std::chrono::high_resolution_clock::now();
            decryptor.decrypt(compare_results[i], plain);
            batch_encoder.decode(plain, slots);
            auto end_dec = std::chrono::high_resolution_clock::now();
            auto us_dec = std::chrono::duration_cast<std::chrono::microseconds>(
                            end_dec - start_dec
                        ).count();
            total_us_dec += us_dec;

            // check
            const uint64_t R          = (1u << r);
            const uint64_t LOWER_MASK = (1u << SHIFT) - 1;  // 0x3FFF

            auto start_check = std::chrono::high_resolution_clock::now();
            for (size_t idx : non_placeholder_indices[h]) {
                uint64_t v  = slots[idx];
                uint64_t lo =  v         & LOWER_MASK;
                uint64_t hi = (v >> SHIFT) & LOWER_MASK;

                if ((lo % R == 0) && (lo / R >= 1)) intersection_count += 1;
                if ((hi % R == 0) && (hi / R >= 1)) intersection_count += 1;
            }
            auto end_check = std::chrono::high_resolution_clock::now();
            auto us_check = std::chrono::duration_cast<std::chrono::microseconds>(
                                end_check - start_check
                            ).count();
            total_us_check += us_check;
        }

        total_intersection_count += intersection_count;
        std::cout << "[client] hash " << h
                << " Intersection count: " << intersection_count << std::endl;
    }

    std::cout << "Total intersection count = " << total_intersection_count << std::endl;
    cout << "latency(hash): " << us_gen_cuc << " us (" << (us_gen_cuc)/ 1000.0 << " ms)" << endl;
    cout << "latency(encryption): " << total_us_enc << " us (" << total_us_enc / 1000.0 << " ms)" << endl;
    cout << "latency(decryption): " << total_us_dec << " us (" << total_us_dec / 1000.0 << " ms)" << endl;
    cout << "latency(check intersection): " << total_us_check << " us (" << total_us_check / 1000.0 << " ms)" << endl;



    // ==== 통신 통계 출력 ====
    double mb_c2s = wire.bytes_sent() / (1024.0 * 1024.0);
    double mb_s2c = wire.bytes_recv() / (1024.0 * 1024.0);

    double ms_send = wire.send_time_us() / 1000.0;
    double ms_recv = wire.recv_time_us() / 1000.0;
    double ms_comm_total = ms_send + ms_recv;

    std::cout << "\n[client] bytes client->server: "
              << wire.bytes_sent() << " B (" << mb_c2s << " MB)\n";
    std::cout << "[client] bytes server->client: "
              << wire.bytes_recv() << " B (" << mb_s2c << " MB)\n";
    std::cout << "[client] time send: " << ms_send << " ms, "
              << "recv: " << ms_recv << " ms, "
              << "total comm time: " << ms_comm_total << " ms\n";


    return 0;
}
