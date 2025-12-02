#pragma once

#include <cstdint>
#include <vector>
#include <sstream>
#include <string>

#include "../network/wire.h"         // 여기서 Wire 클래스를 가져옴
#include "../hashing/hash_params.h"
#include "seal/seal.h"

// 1. raw send/recv 인터페이스
//   - 내부에서 POSIX socket 이나 네가 이미 가진 net::SocketLink 를 사용하면 됨.

// --------- 기본적인 length-prefixed 바이트 전송 ---------

inline void send_u64(Wire& w, std::uint64_t v) {
    w.send_raw(reinterpret_cast<const uint8_t*>(&v), sizeof(v));
}

inline std::uint64_t recv_u64(Wire& w) {
    std::uint64_t v;
    w.recv_raw(reinterpret_cast<uint8_t*>(&v), sizeof(v));
    return v;
}

inline void send_bytes(Wire& w, const std::vector<uint8_t>& buf) {
    send_u64(w, buf.size());
    if (!buf.empty())
        w.send_raw(buf.data(), buf.size());
}

inline std::vector<uint8_t> recv_bytes(Wire& w) {
    auto len = recv_u64(w);
    std::vector<uint8_t> buf(len);
    if (len > 0)
        w.recv_raw(buf.data(), len);
    return buf;
}

// --------- SEAL 객체 직렬화 헬퍼 (내가 말한 send_seal_obj) ---------

template<class T>
void send_seal_obj(Wire& w, const T& obj) {
    std::stringstream ss;
    obj.save(ss);
    std::string s = ss.str();
    std::vector<uint8_t> buf(s.begin(), s.end());
    send_bytes(w, buf);
}

// 1) EncryptionParameters 전용: context 없이 load(stream)
inline void recv_seal_parms(Wire& w, seal::EncryptionParameters& parms) {
    auto buf = recv_bytes(w);
    std::stringstream ss(std::string(buf.begin(), buf.end()));
    parms.load(ss);   // 여기는 원래대로
}

// 2) PublicKey / Ciphertext 등: context가 필요한 버전
template<class T>
void recv_seal_obj(Wire& w, T& obj, const seal::SEALContext& context) {
    auto buf = recv_bytes(w);
    std::stringstream ss(std::string(buf.begin(), buf.end()));
    obj.load(context, ss);   // <- context 필요
}

// --------- HashParams 직렬화 (필드에 맞게 조정 필요) ---------
inline void send_string(Wire& w, const std::string& s) {
    send_u64(w, static_cast<std::uint64_t>(s.size()));
    if (!s.empty()) {
        w.send_raw(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }
}

inline std::string recv_string(Wire& w) {
    std::uint64_t len = recv_u64(w);
    std::string s(len, '\0');
    if (len > 0) {
        w.recv_raw(reinterpret_cast<uint8_t*>(&s[0]), len);
    }
    return s;
}




inline void send_hash_params(Wire& w, const std::vector<HashParams>& hs) {
    send_u64(w, static_cast<std::uint64_t>(hs.size()));
    for (const auto& h : hs) {
        send_u64(w, h.c0);
        send_u64(w, h.c1);
        send_u64(w, h.c2);
        send_u64(w, h.c3);
        send_u64(w, h.prime);
        send_u64(w, h.seed);
        send_u64(w, h.mod);
        send_string(w, h.name);   // 문자열은 길이 + 내용
    }
}

inline std::vector<HashParams> recv_hash_params(Wire& w) {
    std::uint64_t n = recv_u64(w);
    std::vector<HashParams> hs(n);
    for (std::uint64_t i = 0; i < n; ++i) {
        hs[i].c0    = recv_u64(w);
        hs[i].c1    = recv_u64(w);
        hs[i].c2    = recv_u64(w);
        hs[i].c3    = recv_u64(w);
        hs[i].prime = recv_u64(w);
        hs[i].seed  = recv_u64(w);
        hs[i].mod   = recv_u64(w);
        hs[i].name  = recv_string(w);
    }
    return hs;
}
