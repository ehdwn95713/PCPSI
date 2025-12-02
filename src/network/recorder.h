#pragma once
#include <string>
#include <filesystem>
#include <vector>
#include <fstream>
#include <sstream>
#include "seal/seal.h"
#include "../hashing/hash_params.h"

namespace net {

struct RecordOptions {
    bool persist = true;           // 저장 여부
    bool binaries = false;         // CT/PK 실제 저장 (크면 false 권장)
};

class SessionRecorder {
public:
    SessionRecorder(std::string root_dir, std::string session_id, RecordOptions opt);

    // path helper
    std::filesystem::path root() const { return root_dir_; }

    // save file (optional)
    void save_parms(const seal::EncryptionParameters& parms);
    void save_public_key(const seal::PublicKey& pk);
    void save_ciphertext(const seal::Ciphertext& ct, const std::string& relpath);
    // save text file 
    void save_text(const std::string& relpath, const std::string& text);
    // save chosen_hashes (JSON)
    void save_hash_params(const std::vector<HashParams>& hashes,
                          const std::string& relpath = "setup/hash_params.json");
    // text log 
    void append_manifest_line(const std::string& line);

private:
    std::filesystem::path root_dir_;
    RecordOptions opt_;
};

} // namespace net
