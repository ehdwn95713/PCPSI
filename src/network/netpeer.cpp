#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

static void send_all(int fd, const void* buf, size_t len) {
    const char* p = (const char*)buf;
    while (len) { ssize_t n = ::send(fd, p, len, 0); if (n<=0) throw std::runtime_error("send"); p+=n; len-=n; }
}
static void recv_exact(int fd, void* buf, size_t len) {
    char* p = (char*)buf;
    while (len) { ssize_t n = ::recv(fd, p, len, 0); if (n<=0) throw std::runtime_error("recv"); p+=n; len-=n; }
}

int main(int argc, char** argv) {
    int port = 9000;
    if (const char* p = std::getenv("NETPEER_PORT")) port = std::atoi(p);

    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port); addr.sin_addr.s_addr = INADDR_ANY;
    if (::bind(s, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (::listen(s, 16) < 0) { perror("listen"); return 1; }
    std::vector<char> buf;

    while (true) {
        int c = ::accept(s, nullptr, nullptr);
        if (c < 0) continue;
        try {
            for (;;) {
                char op; uint64_t len = 0;
                recv_exact(c, &op, 1);
                recv_exact(c, &len, sizeof(len));
                if (buf.size() < len) buf.resize(len);
                if (op == 'S') {
                    // 클라이언트가 보내는 데이터 받아서 버림
                    if (len) recv_exact(c, buf.data(), (size_t)len);
                } else if (op == 'R') {
                    // 클라이언트가 len 바이트 달라고 요청하면 len 바이트 전송
                    if (len) send_all(c, buf.data(), (size_t)len);
                } else {
                    break;
                }
            }
        } catch (...) {}
        ::close(c);
    }
}
