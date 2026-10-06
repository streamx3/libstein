// SPDX-License-Identifier: MIT
#include "stein_fixture.hpp"
#include "stein_test.hpp"

#include "stein/core/hash.hpp"
#include "stein/fs/filesystem.hpp"
#include "stein/mount/mount.hpp"

#include <filesystem>
#include <fstream>
#include <random>
#include <chrono>
#include <cstdlib>
#include <thread>
#if defined(_WIN32)
#include <windows.h>
#endif

using namespace stein;
using stein::test::loadSparseFixture;

namespace {
// CI sets STEIN_REQUIRE_MOUNT where a backend is expected to work, so a silent skip there is a failure.
void skipOrFail(const std::string& why) {
    const char* require = std::getenv("STEIN_REQUIRE_MOUNT");
    if (require && *require) FAIL(why);
    else MESSAGE(why);
}
} // namespace

TEST_CASE("mount: an ext4 fixture mounted through FUSE reads like the kernel mount did") {
#if defined(__APPLE__)
    ::setenv("STEIN_NFS_DEBUG", "1", 0);   // the request trace shows in the log when mount_nfs fails
#endif
    if (!mount::Mount::available()) {
        skipOrFail("no usable FUSE/WinFsp on this machine; skipping");
        return;
    }
    auto dev = loadSparseFixture("extfs/ext4.sparse");
    auto probed = fs::probe(dev);
    REQUIRE(probed);
    REQUIRE(*probed);
    auto reader = (*probed)->openReader();
    REQUIRE(reader);
#if defined(_WIN32)
    // WinFsp: a free drive letter; files are then reached through "X:\\".
    std::filesystem::path mp;
    {
        const unsigned long drives = GetLogicalDrives();
        for (char letter = 'Z'; letter >= 'E'; --letter)
            if (!(drives & (1u << (letter - 'A')))) {
                mp = std::string(1, letter) + ":";
                break;
            }
    }
    REQUIRE_FALSE(mp.empty());
    const std::filesystem::path base = mp.string() + "\\";
#else
    const auto mp = std::filesystem::temp_directory_path() / ("stein_mount_test_" + std::to_string(std::random_device{}()));
    std::filesystem::create_directories(mp);
    const std::filesystem::path base = mp;
#endif
    auto m = mount::Mount::create(std::move(*reader), mp);
    if (!m) {
        skipOrFail("mount failed (" + m.error().toString() + "); skipping");
#if !defined(_WIN32)
        std::filesystem::remove(mp);
#endif
        return;
    }
    Expected<void> loopResult;
    std::thread loop([&] { loopResult = (*m)->run(); });
    // Never touch the mountpoint unless the loop is serving: a request with no server blocks forever.
    for (int i = 0; i < 200 && !(*m)->running() && loop.joinable(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    if (!(*m)->running()) {
        loop.join();
        skipOrFail("fuse loop did not start: " + (loopResult ? std::string("exited cleanly") : loopResult.error().toString()));
        m->reset();
        std::error_code ec0;
#if !defined(_WIN32)
        std::filesystem::remove(mp, ec0);
#endif
        return;
    }
    // Compare with the oracle through ordinary file APIs.
    std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/extfs/ext4.oracle.txt");
    std::string line;
    int files = 0, dirs = 0, links = 0;
    while (std::getline(in, line)) {
        if (line.rfind("sha256 ", 0) == 0) {
            const auto sp = line.find(' ', 7);
            const std::string path = line.substr(sp + 1), want = line.substr(7, sp - 7);
            std::ifstream f(base / path, std::ios::binary);
            REQUIRE(f);
            std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size()))) == want);
            ++files;
        } else if (line.rfind("link ", 0) == 0) {
            const auto arrow = line.find(" -> ");
            std::error_code ec;
            CHECK(std::filesystem::read_symlink(base / line.substr(5, arrow - 5), ec).generic_string() == line.substr(arrow + 4));
            ++links;
        } else if (line.size() > 2 && line[0] == 'd') {
            std::error_code ec;
            CHECK(std::filesystem::is_directory(base / line.substr(line.find(' ', 2) + 1), ec));
            ++dirs;
        }
    }
    CHECK(files > 300);
    CHECK(dirs >= 5);
    CHECK(links == 2);
    std::error_code ec;
    CHECK_FALSE(std::filesystem::exists(base / "does-not-exist", ec));
    // Read-only: creating a file fails.
    std::ofstream nope(base / "new.txt");
    CHECK_FALSE(nope);
    (*m)->stop();
    loop.join();
    CHECK(loopResult);
    m->reset();
#if !defined(_WIN32)
    std::filesystem::remove(mp, ec);
#endif
}

// ---------------------------------------------------------------- NFS loopback server, driven by a minimal client

#include "stein/mount/nfs_server.hpp"
#include "stein/core/endian.hpp"

#include <map>
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

// Just enough SunRPC/XDR to talk to the server from the test: one TCP connection, one call at a time.
class NfsClient {
public:
    explicit NfsClient(std::uint16_t port) {
#if defined(_WIN32)
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
#endif
        m_sock = static_cast<long long>(::socket(AF_INET, SOCK_STREAM, 0));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        m_ok = ::connect(static_cast<SockT>(m_sock), reinterpret_cast<sockaddr*>(&a), sizeof a) == 0;
    }
    ~NfsClient() {
#if defined(_WIN32)
        closesocket(static_cast<SockT>(m_sock));
#else
        ::close(static_cast<SockT>(m_sock));
#endif
    }
    bool ok() const { return m_ok; }

    struct Reply {
        std::vector<std::byte> data;
        std::size_t pos = 0;
        std::uint32_t u32() {
            const std::uint32_t v = loadBe32(data.data() + pos);
            pos += 4;
            return v;
        }
        std::uint64_t u64() {
            const std::uint64_t hi = u32();
            return (hi << 32) | u32();
        }
        std::vector<std::byte> opaque() {
            const std::uint32_t n = u32();
            std::vector<std::byte> v(data.begin() + static_cast<std::ptrdiff_t>(pos), data.begin() + static_cast<std::ptrdiff_t>(pos + n));
            pos += (n + 3) & ~3u;
            return v;
        }
        std::string str() {
            auto v = opaque();
            return std::string(reinterpret_cast<const char*>(v.data()), v.size());
        }
        void skipFattr() { pos += 84; }
        void skipPostOpAttr() {
            if (u32()) skipFattr();
        }
    };
    // Call prog/vers/proc with the given XDR-encoded args; returns the results after the RPC header.
    Reply call(std::uint32_t prog, std::uint32_t proc, const std::vector<std::byte>& args) {
        std::vector<std::byte> msg;
        auto put = [&](std::uint32_t v) {
            std::byte b[4];
            storeBe32(b, v);
            msg.insert(msg.end(), b, b + 4);
        };
        put(0);   // record mark placeholder
        const std::uint32_t xid = ++m_xid;
        put(xid);
        put(0);   // CALL
        put(2);   // RPC version
        put(prog);
        put(3);
        put(proc);
        // AUTH_SYS credentials like a kernel client: stamp, machine name, uid, gid, no groups.
        put(1);
        put(6 * 4);      // body length: stamp, name length, name, uid, gid, gid count
        put(0);          // stamp
        put(4);          // machine name "test"
        put(0x74657374u);
        put(501);        // uid
        put(20);         // gid
        put(0);          // gids count
        put(0);
        put(0);   // AUTH_NULL verf
        msg.insert(msg.end(), args.begin(), args.end());
        storeBe32(msg.data(), 0x80000000u | static_cast<std::uint32_t>(msg.size() - 4));
        REQUIRE(::send(static_cast<SockT>(m_sock), reinterpret_cast<const char*>(msg.data()), static_cast<int>(msg.size()), 0) == static_cast<int>(msg.size()));
        Reply r;
        std::byte head[4];
        REQUIRE(recvAll(head, 4));
        const std::uint32_t mark = loadBe32(head);
        REQUIRE((mark & 0x80000000u) != 0);
        r.data.resize(mark & 0x7FFFFFFFu);
        REQUIRE(recvAll(r.data.data(), r.data.size()));
        REQUIRE(r.u32() == xid);
        REQUIRE(r.u32() == 1);   // REPLY
        REQUIRE(r.u32() == 0);   // MSG_ACCEPTED
        r.u32();
        r.opaque();              // verf
        REQUIRE(r.u32() == 0);   // SUCCESS
        return r;
    }
    static std::vector<std::byte> fhArg(const std::vector<std::byte>& fh, const std::vector<std::byte>& more = {}) {
        std::vector<std::byte> a;
        std::byte b[4];
        storeBe32(b, static_cast<std::uint32_t>(fh.size()));
        a.insert(a.end(), b, b + 4);
        a.insert(a.end(), fh.begin(), fh.end());
        while (a.size() % 4) a.push_back(std::byte{0});
        a.insert(a.end(), more.begin(), more.end());
        return a;
    }
    static std::vector<std::byte> strArg(std::string_view s) {
        std::vector<std::byte> a;
        std::byte b[4];
        storeBe32(b, static_cast<std::uint32_t>(s.size()));
        a.insert(a.end(), b, b + 4);
        a.insert(a.end(), reinterpret_cast<const std::byte*>(s.data()), reinterpret_cast<const std::byte*>(s.data()) + s.size());
        while (a.size() % 4) a.push_back(std::byte{0});
        return a;
    }
    static void putU32(std::vector<std::byte>& a, std::uint32_t v) {
        std::byte b[4];
        storeBe32(b, v);
        a.insert(a.end(), b, b + 4);
    }
    static void putU64(std::vector<std::byte>& a, std::uint64_t v) {
        putU32(a, static_cast<std::uint32_t>(v >> 32));
        putU32(a, static_cast<std::uint32_t>(v));
    }

private:
#if defined(_WIN32)
    using SockT = SOCKET;
#else
    using SockT = int;
#endif
    bool recvAll(std::byte* p, std::size_t n) {
        std::size_t done = 0;
        while (done < n) {
            const auto got = ::recv(static_cast<SockT>(m_sock), reinterpret_cast<char*>(p + done), static_cast<int>(n - done), 0);
            if (got <= 0) return false;
            done += static_cast<std::size_t>(got);
        }
        return true;
    }
    long long m_sock = -1;
    bool m_ok = false;
    std::uint32_t m_xid = 100;
};

struct NfsEntry {
    std::string name;
    std::vector<std::byte> fh;
    std::uint32_t type = 0;
    std::uint64_t size = 0;
};

// READDIRPLUS everything in `dir`, honouring eof/cookies.
std::vector<NfsEntry> listDir(NfsClient& c, const std::vector<std::byte>& dirFh) {
    std::vector<NfsEntry> out;
    std::uint64_t cookie = 0;
    for (int rounds = 0; rounds < 1000; ++rounds) {
        std::vector<std::byte> more;
        NfsClient::putU64(more, cookie);
        NfsClient::putU64(more, 0);
        NfsClient::putU32(more, 4096);
        NfsClient::putU32(more, 8192);
        auto r = c.call(100003, 17, NfsClient::fhArg(dirFh, more));
        REQUIRE(r.u32() == 0);
        r.skipPostOpAttr();
        r.u64();
        while (r.u32()) {
            NfsEntry e;
            r.u64();
            e.name = r.str();
            cookie = r.u64();
            if (r.u32()) {   // fattr3: type, mode, nlink, uid, gid, size, used, rdev, fsid, fileid, 3 times
                e.type = r.u32();
                r.pos += 16;
                e.size = r.u64();
                r.pos += 84 - 28;
            }
            if (r.u32()) e.fh = r.opaque();
            if (e.name != "." && e.name != "..") out.push_back(std::move(e));
        }
        if (r.u32()) break;   // eof
    }
    return out;
}

void walkNfs(NfsClient& c, const std::vector<std::byte>& dirFh, const std::string& prefix, std::map<std::string, std::string>& sha, std::map<std::string, std::string>& links, int& dirs) {
    for (const auto& e : listDir(c, dirFh)) {
        const std::string path = prefix.empty() ? e.name : prefix + "/" + e.name;
        // LOOKUP must agree with READDIRPLUS.
        auto lk = c.call(100003, 3, NfsClient::fhArg(dirFh, NfsClient::strArg(e.name)));
        REQUIRE(lk.u32() == 0);
        CHECK(lk.opaque() == e.fh);
        if (e.type == 2) {
            ++dirs;
            walkNfs(c, e.fh, path, sha, links, dirs);
        } else if (e.type == 5) {
            auto rl = c.call(100003, 5, NfsClient::fhArg(e.fh));
            REQUIRE(rl.u32() == 0);
            rl.skipPostOpAttr();
            links[path] = rl.str();
        } else if (e.type == 1) {
            std::vector<std::byte> data;
            for (;;) {
                std::vector<std::byte> more;
                NfsClient::putU64(more, data.size());
                NfsClient::putU32(more, 65536);
                auto rd = c.call(100003, 6, NfsClient::fhArg(e.fh, more));
                REQUIRE(rd.u32() == 0);
                rd.skipPostOpAttr();
                const std::uint32_t count = rd.u32();
                const bool eof = rd.u32() != 0;
                auto chunk = rd.opaque();
                REQUIRE(chunk.size() == count);
                data.insert(data.end(), chunk.begin(), chunk.end());
                if (eof || count == 0) break;
            }
            CHECK(data.size() == e.size);
            sha[path] = Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, data));
        }
    }
}

} // namespace

TEST_CASE("nfs server: the ext4 fixture served over NFSv3 reads like the kernel mount did (MNT, LOOKUP, READDIRPLUS, READ, READLINK, ACCESS, FSINFO)") {
    auto dev = loadSparseFixture("extfs/ext4.sparse");
    auto probed = fs::probe(dev);
    REQUIRE(probed);
    auto reader = (*probed)->openReader();
    REQUIRE(reader);
    auto server = mount::NfsServer::start(std::move(*reader));
    REQUIRE_MESSAGE(server, (server ? std::string() : server.error().toString()));
    CHECK((*server)->port() != 0);
    NfsClient c((*server)->port());
    REQUIRE(c.ok());
    // MOUNT: NULL, EXPORT, MNT
    c.call(100005, 0, {});
    auto ex = c.call(100005, 5, {});
    CHECK(ex.u32() == 1);
    CHECK(ex.str() == "/");
    auto mnt = c.call(100005, 1, NfsClient::strArg("/"));
    REQUIRE(mnt.u32() == 0);
    const auto rootFh = mnt.opaque();
    REQUIRE(rootFh.size() == 8);
    // FSINFO and ACCESS on the root
    auto fsinfo = c.call(100003, 19, NfsClient::fhArg(rootFh));
    CHECK(fsinfo.u32() == 0);
    std::vector<std::byte> accessArg;
    NfsClient::putU32(accessArg, 0x3F);
    auto acc = c.call(100003, 4, NfsClient::fhArg(rootFh, accessArg));
    CHECK(acc.u32() == 0);
    acc.skipPostOpAttr();
    CHECK(acc.u32() == (1u | 2u | 32u));   // read, lookup, execute; never modify
    // WRITE is refused on a read-only export.
    std::vector<std::byte> wr;
    NfsClient::putU64(wr, 0);
    NfsClient::putU32(wr, 4);
    NfsClient::putU32(wr, 0);
    NfsClient::putU32(wr, 4);
    NfsClient::putU32(wr, 0x61626364);
    auto w = c.call(100003, 7, NfsClient::fhArg(rootFh, wr));
    CHECK(w.u32() == 30);
    // Whole tree against the oracle.
    std::map<std::string, std::string> sha, links;
    int dirs = 0;
    walkNfs(c, rootFh, "", sha, links, dirs);
    std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/extfs/ext4.oracle.txt");
    REQUIRE(in);
    std::string line;
    int files = 0, linkCount = 0;
    while (std::getline(in, line)) {
        if (line.rfind("sha256 ", 0) == 0) {
            const auto sp = line.find(' ', 7);
            const std::string path = line.substr(sp + 1), want = line.substr(7, sp - 7);
            CAPTURE(path);
            CHECK(sha[path] == want);
            ++files;
        } else if (line.rfind("link ", 0) == 0) {
            const auto arrow = line.find(" -> ");
            CHECK(links[line.substr(5, arrow - 5)] == line.substr(arrow + 4));
            ++linkCount;
        }
    }
    CHECK(files > 300);
    CHECK(dirs >= 5);
    CHECK(linkCount == 2);
    CHECK((*server)->requests() > 600);
    auto missing = c.call(100003, 3, NfsClient::fhArg(rootFh, NfsClient::strArg("does-not-exist")));
    CHECK(missing.u32() == 2);   // NFS3ERR_NOENT
    (*server)->stop();
}
