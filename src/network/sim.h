#pragma once
#include <cstddef>
#include <vector>
#include <string>
#include "profile.h"
#include "messages.h"

namespace net {

// 전송 시뮬레이터: 바이트 수와 프로파일로 시간만 계산/누적
class NetworkLink {
public:
    explicit NetworkLink(NetProfile p) : prof_(p) {}
    const NetProfile& profile() const { return prof_; }

    // 편도 전송 시간(초) 반환 + 누적
    double send_bytes(size_t bytes);
    // 편도 수신도 동일 모델(계산만)
    double recv_bytes(size_t bytes) { return send_bytes(bytes); }

    // 왕복(업/다운) 합산
    double roundtrip(size_t up_bytes, size_t down_bytes);

    // 누적 시간(ms)
    double elapsed_ms() const { return elapsed_ms_; }

private:
    NetProfile prof_;
    double elapsed_ms_ = 0.0;
};

} // namespace net
