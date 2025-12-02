#pragma once
#include <string>
#include <cstdint>
#include <stdexcept>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

class Wire {
    int sock_ = -1;

    static int checked(int ret, const char* msg) {
        if (ret < 0) {
            perror(msg);
            throw std::runtime_error(msg);
        }
        return ret;
    }

public:
    // ==== 클라이언트용: host, port 받아서 connect ====
    Wire(const std::string& host, int port) {
        sock_ = checked(::socket(AF_INET, SOCK_STREAM, 0), "socket");

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
        checked(::inet_pton(AF_INET, host.c_str(), &addr.sin_addr), "inet_pton");

        checked(::connect(sock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), "connect");
    }

    // ==== 서버용: 포트만 받아서 listen 후 한 번 accept ====
    explicit Wire(int port) {
        int listen_fd = checked(::socket(AF_INET, SOCK_STREAM, 0), "socket(listen)");

        int opt = 1;
        ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(port);
        checked(::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), "bind");
        checked(::listen(listen_fd, 1), "listen");

        sockaddr_in cli_addr{};
        socklen_t cli_len = sizeof(cli_addr);
        sock_ = checked(::accept(listen_fd, reinterpret_cast<sockaddr*>(&cli_addr), &cli_len), "accept");

        ::close(listen_fd);
    }

    ~Wire() {
        if (sock_ >= 0) {
            ::close(sock_);
        }
    }

    void send_raw(const uint8_t* data, size_t len) {
        size_t sent = 0;
        while (sent < len) {
            ssize_t r = ::send(sock_, data + sent, len - sent, 0);
            if (r <= 0) throw std::runtime_error("send failed");
            sent += static_cast<size_t>(r);
        }
    }

    void recv_raw(uint8_t* data, size_t len) {
        size_t recvd = 0;
        while (recvd < len) {
            ssize_t r = ::recv(sock_, data + recvd, len - recvd, 0);
            if (r <= 0) throw std::runtime_error("recv failed");
            recvd += static_cast<size_t>(r);
        }
    }
};



// #pragma once
// #include <cstddef>
// #include <sstream>
// #include <vector>
// #include <string>
// #include "seal/seal.h"

namespace net {

// Helper to measure serialized byte size of SEAL objects
inline size_t size_bytes(const seal::Ciphertext& ct) {
    std::ostringstream oss(std::ios::binary);
    ct.save(oss);
    return static_cast<size_t>(oss.tellp());
}
inline size_t size_bytes(const seal::PublicKey& pk) {
    std::ostringstream oss(std::ios::binary);
    pk.save(oss);
    return static_cast<size_t>(oss.tellp());
}
inline size_t size_bytes(const seal::EncryptionParameters& parms) {
    std::ostringstream oss(std::ios::binary);
    parms.save(oss);
    return static_cast<size_t>(oss.tellp());
}
inline size_t size_bytes_vec(const std::vector<seal::Ciphertext>& v) {
    size_t s = 0; for (const auto& x : v) s += size_bytes(x); return s;
}
inline size_t size_bytes_vec2(const std::vector<std::vector<seal::Ciphertext>>& v2) {
    size_t s = 0; for (const auto& v : v2) s += size_bytes_vec(v); return s;
}

// Hash parameters (if no user-defined serialization, approximate size)
// If serialized to JSON string, the length of the string can also be used.
template<class HashParams>
size_t size_bytes_hash_params(const std::vector<HashParams>& hp_vec) {
    // Rough estimate: ~64–80B per entry (7 fields * 8 bytes), padded to 96B
    return hp_vec.size() * 96;
}

} // namespace net
