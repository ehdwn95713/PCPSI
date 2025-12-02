#pragma once
#include <string>

namespace net {

struct NetProfile {
    std::string name;
    double rtt_ms;               // (ms)
    double bandwidth_mbps;       // (Mbps)
    size_t per_msg_overhead_B;   // (byte)
};

inline NetProfile LAN(double rtt_ms = 0.2, double bw_mbps = 10000.0) {
    return NetProfile{ "LAN", rtt_ms, bw_mbps, 64 };
}

inline NetProfile WAN(double rtt_ms = 80.0, double bw_mbps = 100.0) {
    return NetProfile{ "WAN", rtt_ms, bw_mbps, 64 };
}

} // namespace net
