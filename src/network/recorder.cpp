#include "recorder.h"
#include <chrono>

namespace net {

static void ensure_dir(const std::filesystem::path& p) {
    std::error_code ec;
    std::filesystem::create_directories(p, ec);
}

SessionRecorder::SessionRecorder(std::string root_dir, std::string session_id, RecordOptions opt)
: root_dir_(std::filesystem::path(root_dir) / session_id), opt_(opt)
{
    if (!opt_.persist) return;
    ensure_dir(root_dir_);
    ensure_dir(root_dir_ / "setup");
    ensure_dir(root_dir_ / "client_to_server");
    ensure_dir(root_dir_ / "server_to_client");
    std::ofstream(root_dir_ / "manifest.txt") << "session=" << session_id << "\n";
}

void SessionRecorder::save_parms(const seal::EncryptionParameters& parms) {
    if (!opt_.persist || !opt_.binaries) return;
    std::ostringstream oss(std::ios::binary);
    parms.save(oss);
    std::ofstream f(root_dir_ / "setup" / "parms.bin", std::ios::binary);
    f.write(oss.str().data(), (std::streamsize)oss.str().size());
}

void SessionRecorder::save_public_key(const seal::PublicKey& pk) {
    if (!opt_.persist || !opt_.binaries) return;
    std::ostringstream oss(std::ios::binary);
    pk.save(oss);
    std::ofstream f(root_dir_ / "setup" / "public_key.bin", std::ios::binary);
    f.write(oss.str().data(), (std::streamsize)oss.str().size());
}

void SessionRecorder::save_ciphertext(const seal::Ciphertext& ct, const std::string& relpath) {
    if (!opt_.persist || !opt_.binaries) return;
    std::ostringstream oss(std::ios::binary);
    ct.save(oss);
    auto full = root_dir_ / relpath;
    ensure_dir(full.parent_path());
    std::ofstream f(full, std::ios::binary);
    f.write(oss.str().data(), (std::streamsize)oss.str().size());
}
void SessionRecorder::save_text(const std::string& relpath, const std::string& text) {
    if (!opt_.persist) return;
    auto full = root_dir_ / relpath;
    ensure_dir(full.parent_path());
    std::ofstream f(full);
    f << text;
}
// chosen_hashes -> JSON
void SessionRecorder::save_hash_params(const std::vector<HashParams>& hashes,
                                       const std::string& relpath) {
    if (!opt_.persist) return;

    std::ostringstream json;
    json << "{\n  \"hash_params\": [\n";
    for (size_t i = 0; i < hashes.size(); ++i) {
        const auto& h = hashes[i];
        // HashParams { c0,c1,c2,c3,prime,seed,mod,name } 가정
        json << "    {"
             << "\"name\":\"" << h.name << "\","
             << "\"c0\":"   << h.c0   << ","
             << "\"c1\":"   << h.c1   << ","
             << "\"c2\":"   << h.c2   << ","
             << "\"c3\":"   << h.c3   << ","
             << "\"prime\":"<< h.prime<< ","
             << "\"seed\":" << h.seed << ","
             << "\"mod\":"  << h.mod
             << "}";
        if (i + 1 < hashes.size()) json << ",";
        json << "\n";
    }
    json << "  ]\n}\n";

    save_text(relpath, json.str());
}

void SessionRecorder::append_manifest_line(const std::string& line) {
    if (!opt_.persist) return;
    std::ofstream f(root_dir_ / "manifest.txt", std::ios::app);
    f << line << "\n";
}

} // namespace net
