// server_test.cpp
#include "seal/seal.h"
#include "network/wire.h"
#include "network/psi_wire.h"

#include <iostream>
#include <vector>
#include <cstdint>
#include <chrono>

using clock_type = std::chrono::high_resolution_clock;

int main(int argc, char** argv) {
    // ==== 여기서 서버가 보낼 payload 크기를 설정 ====
    // 예: 4MB
    const std::uint64_t SERVER_SEND_BYTES = 4ull * 1024 * 1024;

    int port = 9000;
    if (argc > 1) {
        port = std::stoi(argv[1]);
    }

    try {
        std::cout << "[SERVER] Listening on port " << port << "...\n";
        Wire w(port);  // 한 번 accept하는 서버 생성자

        std::cout << "[SERVER] Client connected.\n";

        // ---------- 클라이언트 → 서버 시간 측정 ----------
        auto t_recv_start = clock_type::now();

        std::uint64_t client_len = recv_u64(w);
        std::cout << "[SERVER] Expecting " << client_len << " bytes from client.\n";

        std::vector<uint8_t> client_buf(client_len);
        if (client_len > 0) {
            w.recv_raw(client_buf.data(), client_buf.size());
        }

        auto t_recv_end = clock_type::now();

        // ---------- 서버 → 클라이언트 시간 측정 ----------
        std::vector<uint8_t> server_buf(SERVER_SEND_BYTES, 0xAB); // dummy data

        auto t_send_start = clock_type::now();

        send_u64(w, SERVER_SEND_BYTES);
        if (!server_buf.empty()) {
            w.send_raw(server_buf.data(), server_buf.size());
        }

        auto t_send_end = clock_type::now();

        // 시간(ms) 계산
        double c2s_ms = std::chrono::duration<double, std::milli>(t_recv_end - t_recv_start).count();
        double s2c_ms = std::chrono::duration<double, std::milli>(t_send_end - t_send_start).count();

        std::cout << "\n[SERVER] === Stats ===\n";
        std::cout << "  Client send bytes (C->S): " << client_len        << "\n";
        std::cout << "  Server send bytes (S->C): " << SERVER_SEND_BYTES << "\n";
        std::cout << "  C->S one-way time (ms):   " << c2s_ms            << "\n";
        std::cout << "  S->C one-way time (ms):   " << s2c_ms            << "\n";

    } catch (const std::exception& e) {
        std::cerr << "[SERVER] Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
