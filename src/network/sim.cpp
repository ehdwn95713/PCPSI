#include "sim.h"
#include <iostream>

namespace net {

static inline double xfer_seconds(size_t bytes, double bandwidth_mbps) {
    // Mbps -> B/s : Mbps * 1e6 / 8
    double Bs = bandwidth_mbps * 1e6 / 8.0;
    return bytes / Bs;
}

double NetworkLink::send_bytes(size_t bytes) {
    // 전송 + 편도 전파 지연(RTT/2) + 고정 오버헤드 전송 시간
    double sec = xfer_seconds(bytes + prof_.per_msg_overhead_B, prof_.bandwidth_mbps);
    sec += (prof_.rtt_ms / 2.0) / 1000.0;
    elapsed_ms_ += sec * 1000.0;
    return sec;
}

double NetworkLink::roundtrip(size_t up_bytes, size_t down_bytes) {
    double sec = 0.0;
    sec += send_bytes(up_bytes);   // 업
    sec += send_bytes(down_bytes); // 다운 (편도 모델 재사용)
    // 위에서 편도마다 RTT/2를 더했으니 왕복은 총 RTT 1회를 더한 효과
    return sec;
}

} // namespace net
