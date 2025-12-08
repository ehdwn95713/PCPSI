// client_test.cpp
#include "seal/seal.h"
#include "network/wire.h"
#include "network/psi_wire.h"

#include <iostream>
#include <vector>
#include <cstdint>
#include <chrono>

using clock_type = std::chrono::high_resolution_clock;

int main(int argc, char** argv) {
    // ==== 여기서 클라이언트가 보낼 payload 크기를 설정 ====
    // 예: 2MB
    const std::uint64_t CLIENT_SEND_BYTES = 2ull * 1024 * 1024;

    std::string host = "127.0.0.1";
    int port = 9000;

    if (argc > 1) host = argv[1];
    if (argc > 2) port = std::stoi(argv[2]);

    try {
        std::cout << "[CLIENT] Connecting to " << host << ":" << port << "...\n";
        Wire w(host, port);
        std::cout << "[CLIENT] Connected.\n";

        // 전송할 dummy 데이터 준비
        std::vector<uint8_t> send_buf(CLIENT_SEND_BYTES, 0xCD);

        // ---------- 클라이언트 → 서버 시간 측정 ----------
        auto t_send_start = clock_type::now();

        // 1) 길이 + 데이터 전송
        send_u64(w, CLIENT_SEND_BYTES);
        if (!send_buf.empty()) {
            w.send_raw(send_buf.data(), send_buf.size());
        }

        auto t_send_end = clock_type::now();

        // ---------- 서버 → 클라이언트 시간 측정 ----------
        auto t_recv_start = clock_type::now();

        // 2) 서버로부터 길이 + 데이터 수신
        std::uint64_t server_len = recv_u64(w);
        std::vector<uint8_t> recv_buf(server_len);
        if (server_len > 0) {
            w.recv_raw(recv_buf.data(), recv_buf.size());
        }

        auto t_recv_end = clock_type::now();

        // 시간(ms) 계산
        double c2s_ms = std::chrono::duration<double, std::milli>(t_send_end - t_send_start).count();
        double s2c_ms = std::chrono::duration<double, std::milli>(t_recv_end - t_recv_start).count();
        double rtt_ms = std::chrono::duration<double, std::milli>(t_recv_end - t_send_start).count();

        std::cout << "\n[CLIENT] === Stats ===\n";
        std::cout << "  Client send bytes (C->S): " << CLIENT_SEND_BYTES << "\n";
        std::cout << "  Server send bytes (S->C): " << server_len        << "\n";
        std::cout << "  C->S one-way time (ms):   " << c2s_ms            << "\n";
        std::cout << "  S->C one-way time (ms):   " << s2c_ms            << "\n";
        std::cout << "  RTT (C->S->C) (ms):       " << rtt_ms            << "\n";

    } catch (const std::exception& e) {
        std::cerr << "[CLIENT] Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
