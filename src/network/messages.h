#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace net {

// message type identification
enum class MsgKind {
    SetupParams, PublicKey, HashParams, QueryCTs, ResultCTs, Ack, Stats
};

struct MsgSize {
    MsgKind kind;
    size_t bytes = 0;
};

} // namespace net
