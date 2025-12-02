// network/socket_link.cpp
#include "socket_link.h"

#include <stdexcept>
#include <cstring>
#include <chrono>
#include <vector>
#include <thread>
#include <algorithm>
#include <cstdlib>
#include <cmath>
#include <cstdint>

// POSIX sockets
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <unistd.h>

using namespace std::chrono;

namespace net {

// Ethernet MTU and headers (no options)
static constexpr std::size_t TCP_HEADER_BYTES = 20;
static constexpr std::size_t IP_HEADER_BYTES  = 20;
static constexpr std::size_t HEADER_BYTES     = TCP_HEADER_BYTES + IP_HEADER_BYTES; // 40
static constexpr std::size_t MTU_BYTES        = 1500;
static constexpr std::size_t PAYLOAD_BYTES    = MTU_BYTES - HEADER_BYTES;           // 1460

// -------- env util --------
template <class T>
static T env_or(const char* k, T def);

template <>
double env_or<double>(const char* k, double def) {
    if (const char* v = std::getenv(k)) {
        char* end = nullptr;
        double x = std::strtod(v, &end);
        if (end && end != v) return x;
    }
    return def;
}
template <>
int env_or<int>(const char* k, int def) {
    if (const char* v = std::getenv(k)) {
        char* end = nullptr;
        long x = std::strtol(v, &end, 10);
        if (end && end != v) return static_cast<int>(x);
    }
    return def;
}

// -------- socket I/O --------
void SocketLink::connect_or_throw(const std::string& host, int port) {
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;

    std::string port_s = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res);
    if (rc != 0) throw std::runtime_error(std::string("getaddrinfo: ") + gai_strerror(rc));

    int fd = -1;
    for (auto p = res; p; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) throw std::runtime_error("connect failed");

    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    fd_ = fd;

    // Apply 1 RTT on TCP handshake
    std::this_thread::sleep_for(std::chrono::milliseconds(handshake_rtt_ms_));
    elapsed_ms_ += handshake_rtt_ms_;
}

SocketLink::SocketLink(const std::string& host, int port,
                       int handshake_rtt_ms, double bandwidth_bps_up)
    : handshake_rtt_ms_(handshake_rtt_ms),
      bandwidth_up_bps_(bandwidth_bps_up),
      bandwidth_down_bps_(bandwidth_bps_up)
{
    // Tunables via env
    handshake_rtt_ms_   = env_or<int>("RTT_MS", handshake_rtt_ms_);
    bandwidth_up_bps_   = env_or<double>("BANDWIDTH_BPS_UP",   bandwidth_up_bps_);
    bandwidth_down_bps_ = env_or<double>("BANDWIDTH_BPS_DOWN", bandwidth_down_bps_);

    init_cwnd_segs_     = std::max(1, env_or<int>("INIT_CWND", 10));
    ssthresh_segs_      = std::max(2, env_or<int>("SSTHRESH", 32));
    ack_ratio_          = std::max(1, env_or<int>("ACK_RATIO", 2));
    server_proc_ms_     = std::max(0, env_or<int>("PROC_MS", 0));

    max_cwnd_segs_      = std::max(2, env_or<int>("MAX_CWND", 256));
    ack_timer_ms_       = std::max(50, env_or<int>("ACK_TIMER_MS", 200));
    idle_reset_ms_      = std::max(0,  env_or<int>("IDLE_RESET_MS", 500));
    bdp_cap_factor_     = std::max(0.1, env_or<double>("BDP_FACTOR", 0.75));

    // Initialize connection-level cwnd
    cwnd_segs_    = static_cast<std::size_t>(init_cwnd_segs_);
    last_activity_ = std::chrono::steady_clock::now();

    connect_or_throw(host, port);
}

SocketLink::~SocketLink() {
    if (fd_ >= 0) ::close(fd_);
}

void SocketLink::send_all(int fd, const void* buf, std::size_t len) {
    const char* p = static_cast<const char*>(buf);
    while (len > 0) {
        ssize_t n = ::send(fd, p, len, 0);
        if (n <= 0) throw std::runtime_error("send failed");
        p += n; len -= static_cast<std::size_t>(n);
    }
}

void SocketLink::recv_exact(int fd, void* buf, std::size_t len) {
    char* p = static_cast<char*>(buf);
    while (len > 0) {
        ssize_t n = ::recv(fd, p, len, 0);
        if (n <= 0) throw std::runtime_error("recv failed");
        p += n; len -= static_cast<std::size_t>(n);
    }
}

// Shrink cwnd after long idle to avoid burst
void SocketLink::on_start_transfer() {
    auto now = std::chrono::steady_clock::now();
    auto idle_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_activity_).count();
    if (idle_reset_ms_ > 0 && idle_ms > idle_reset_ms_) {
        cwnd_segs_ = std::max<std::size_t>(static_cast<std::size_t>(init_cwnd_segs_), cwnd_segs_ / 2);
    }
}

// BDP-based cap: cap cwnd to a fraction of BDP (conservative)
std::size_t SocketLink::cap_cwnd_by_bdp(bool is_upload) {
    double bps = is_upload ? bandwidth_up_bps_ : bandwidth_down_bps_;
    if (bps <= 0) return static_cast<std::size_t>(max_cwnd_segs_); // unlimited bandwidth
    double rtt_s = std::max(1, handshake_rtt_ms_) / 1000.0;
    // BDP(bits) = bps * rtt; segments = BDP / (payload_bits_per_seg)
    double bdp_segs = (bps * rtt_s) / (PAYLOAD_BYTES * 8.0);
    std::size_t cap = static_cast<std::size_t>(std::floor(bdp_segs * bdp_cap_factor_));
    cap = std::max<std::size_t>(2, std::min<std::size_t>(cap, static_cast<std::size_t>(max_cwnd_segs_)));
    return cap;
}

// Core transfer loop using connection-level cwnd
double SocketLink::transfer_flight_model(std::size_t bytes, bool is_upload) {
    std::size_t segments_total = static_cast<std::size_t>((bytes + PAYLOAD_BYTES - 1) / PAYLOAD_BYTES);

    static thread_local std::vector<char> buf;
    if (buf.size() < bytes) buf.resize(bytes);

    // Simple protocol header: action + length
    {
        char hdr = is_upload ? 'S' : 'R';
        std::uint64_t len = bytes;
        send_all(fd_, &hdr, 1);
        send_all(fd_, &len, sizeof(len));
    }

    on_start_transfer();

    auto t0 = steady_clock::now();

    std::size_t seg_done = 0;
    std::size_t byte_cursor = 0;

    while (seg_done < segments_total) {
        // Apply conservative cap to current cwnd
        std::size_t cwnd_cap = cap_cwnd_by_bdp(is_upload);
        if (cwnd_segs_ > cwnd_cap) cwnd_segs_ = cwnd_cap;
        std::size_t flight = std::min(cwnd_segs_, segments_total - seg_done);
        if (flight == 0) flight = 1; // safety

        // 1) Push the flight (MTU-sized chunks)
        std::size_t seg_in_flight = 0;
        while (seg_in_flight < flight) {
            std::size_t chunk = std::min<std::size_t>(PAYLOAD_BYTES, bytes - byte_cursor);
            if (is_upload) {
                send_all(fd_, buf.data() + byte_cursor, chunk);
            } else {
                recv_exact(fd_, buf.data() + byte_cursor, chunk);
            }
            byte_cursor   += chunk;
            seg_in_flight += 1;
        }

        // 2) Transmission time at link rate (one-way serialization)
        double link_bps = is_upload ? bandwidth_up_bps_ : bandwidth_down_bps_;
        double t_tx = 0.0;
        if (link_bps > 0) {
            const double bits = static_cast<double>(flight * PAYLOAD_BYTES) * 8.0;
            t_tx = bits / link_bps;
        }

        // 3) ACK wait: delayed ACK model with timer cap
        double t_rtt = std::max(1, handshake_rtt_ms_) / 1000.0;
        double t_ack = std::min(t_rtt / std::max(1, ack_ratio_), ack_timer_ms_ / 1000.0);

        // 4) Optional server processing time per flight
        double t_proc = std::max(0, server_proc_ms_) / 1000.0;

        double t_sleep = t_tx + t_ack + t_proc;
        if (t_sleep > 0) {
            std::this_thread::sleep_for(std::chrono::duration<double>(t_sleep));
            elapsed_ms_ += t_sleep * 1000.0;
        }

        // 5) cwnd update (kept across calls)
        if (cwnd_segs_ < static_cast<std::size_t>(ssthresh_segs_)) {
            // slow start: double, capped by BDP
            cwnd_segs_ = std::min(cwnd_segs_ * 2, cap_cwnd_by_bdp(is_upload));
        } else {
            // congestion avoidance: +1, capped by BDP
            cwnd_segs_ = std::min(cwnd_segs_ + 1, cap_cwnd_by_bdp(is_upload));
        }

        seg_done      += flight;
        last_activity_ = std::chrono::steady_clock::now();
    }

    auto t1 = steady_clock::now();
    return duration<double>(t1 - t0).count();
}

// Public APIs
double SocketLink::send_bytes(std::size_t bytes) {
    return transfer_flight_model(bytes, /*is_upload=*/true);
}
double SocketLink::recv_bytes(std::size_t bytes) {
    return transfer_flight_model(bytes, /*is_upload=*/false);
}
double SocketLink::roundtrip(std::size_t up_bytes, std::size_t down_bytes) {
    double t_up   = send_bytes(up_bytes);
    double t_down = recv_bytes(down_bytes);
    return t_up + t_down;
}

} // namespace net