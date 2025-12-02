// network/socket_link.h
// Connection-level TCP-like simulator:
// - Real TCP socket connect + handshake RTT once
// - MTU fragmentation (1500B, TCP/IP headers=40B -> payload=1460B)
// - Up/Down bandwidth (bps) with per-flight serialization time
// - Congestion control with connection-level cwnd (kept across calls):
//     slow start (x2 per RTT) -> congestion avoidance (+1 per RTT)
// - Conservative caps via BDP (bandwidth-delay product)
// - Delayed ACK model: min(RTT / ACK_RATIO, ACK_TIMER_MS)
// - Idle shrink: if no activity for a while, reduce cwnd
//
// Env overrides (optional):
//   RTT_MS                : int (ms)
//   BANDWIDTH_BPS_UP      : double (bps)
//   BANDWIDTH_BPS_DOWN    : double (bps)
//   INIT_CWND             : int (segments, default 10)
//   SSTHRESH              : int (segments, default 32)
//   MAX_CWND              : int (segments, default 256)
//   ACK_RATIO             : int (segments per ACK, default 2)
//   ACK_TIMER_MS          : int (ms, default 200)
//   BDP_FACTOR            : double (0.1..1.0, default 0.75)
//   IDLE_RESET_MS         : int (ms, default 500)
//   PROC_MS               : int (ms per flight, default 0)

#pragma once
#include <cstddef>
#include <string>
#include <chrono>

namespace net {

class SocketLink {
public:
    SocketLink(const std::string& host, int port,
               int handshake_rtt_ms, double bandwidth_bps_up);
    ~SocketLink();

    // Send/receive exactly 'bytes' of application payload.
    // Returns wall-clock seconds spent inside the function (sleep + I/O).
    double send_bytes(std::size_t bytes);
    double recv_bytes(std::size_t bytes);

    // Convenience: up then down; returns sum of both durations.
    double roundtrip(std::size_t up_bytes, std::size_t down_bytes);

    // Accumulated simulated time (ms) added by sleeps (handshake, tx, ACK wait, proc).
    double elapsed_ms() const { return elapsed_ms_; }

    // Current RTT parameter (ms).
    int rtt_ms() const { return handshake_rtt_ms_; }

private:
    // Socket primitives
    void connect_or_throw(const std::string& host, int port);
    static void send_all(int fd, const void* buf, std::size_t len);
    static void recv_exact(int fd, void* buf, std::size_t len);

    // Core transfer (uses connection-level cwnd and updates it)
    double transfer_flight_model(std::size_t bytes, bool is_upload);

    // Connection-level helpers
    void on_start_transfer();           // shrink cwnd after idle
    std::size_t cap_cwnd_by_bdp(bool is_upload); // BDP-based conservative cap

private:
    int fd_ = -1;

    // Timing / bandwidth
    int    handshake_rtt_ms_   = 0;
    double bandwidth_up_bps_   = 0.0;
    double bandwidth_down_bps_ = 0.0;

    // Congestion control (in segments; one segment == MTU payload)
    int init_cwnd_segs_ = 10;  // RFC 6928 guidance
    int ssthresh_segs_  = 32;  // conservative default
    int ack_ratio_      = 2;   // delayed ACK: 1 ACK per N segments

    // Conservative tuning
    int    max_cwnd_segs_  = 256;  // hard upper bound
    int    ack_timer_ms_   = 200;  // delayed-ACK timer cap
    int    idle_reset_ms_  = 500;  // shrink cwnd if idle longer than this
    double bdp_cap_factor_ = 0.75; // cap cwnd at 75% of BDP

    // Connection-level cwnd state (persist across calls)
    std::size_t cwnd_segs_ = 10;
    std::chrono::steady_clock::time_point last_activity_ = std::chrono::steady_clock::now();

    // Optional server processing time per flight
    int server_proc_ms_ = 0;

    // Accumulated simulated time (ms)
    double elapsed_ms_ = 0.0;
};

} // namespace net