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

// ---------------------------------------------------------------- the mount from the OS side: external unmount, LUKS end to end

#if !defined(_WIN32)
#include "stein/container/luks.hpp"

#include <set>
#include <sys/stat.h>
#if defined(__APPLE__)
#include <sys/mount.h>
#include <sys/param.h>
#endif

namespace {

// A reader mounted at a fresh temp directory and served from its own thread. The destructor
// stops the loop, joins it and removes the directory, so a failing assertion leaves no mount.
struct LiveMount {
    std::filesystem::path mp;
    std::unique_ptr<stein::mount::Mount> mount;
    std::thread loop;
    Expected<void> loopResult;
    std::string skipWhy;   // set when no mount could be made: the test skips (or fails under STEIN_REQUIRE_MOUNT)

    LiveMount(std::unique_ptr<fs::Reader> reader, const stein::mount::MountOptions& options) {
        mp = std::filesystem::temp_directory_path() / ("stein_mount_test_" + std::to_string(std::random_device{}()));
        std::filesystem::create_directories(mp);
        auto m = stein::mount::Mount::create(std::move(reader), mp, options);
        if (!m) {
            skipWhy = "mount failed (" + m.error().toString() + "); skipping";
            return;
        }
        mount = std::move(*m);
        loop = std::thread([this] { loopResult = mount->run(); });
        // Never touch the mountpoint unless the loop is serving: a request with no server blocks forever.
        for (int i = 0; i < 200 && !mount->running(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (!mount->running()) {
            loop.join();
            skipWhy = "serving loop did not start: " + (loopResult ? std::string("exited cleanly") : loopResult.error().toString());
            mount.reset();
        }
    }
    // True when run() returned on its own within `limit` (the loop is joined then).
    bool waitForExit(std::chrono::milliseconds limit) {
        const auto deadline = std::chrono::steady_clock::now() + limit;
        while (mount->running() && std::chrono::steady_clock::now() < deadline) std::this_thread::sleep_for(std::chrono::milliseconds(20));
        if (mount->running()) return false;
        loop.join();
        return true;
    }
    ~LiveMount() {
        if (mount) mount->stop();
        if (loop.joinable()) loop.join();
        mount.reset();
        std::error_code ec;
        std::filesystem::remove(mp, ec);
    }
};

// What the user does: umount (macOS) / fusermount3 -u (Linux) in a shell, not through stop().
int unmountFromOutside(const std::filesystem::path& mp) {
#if defined(__APPLE__)
    const std::string cmd = "/sbin/umount '" + mp.string() + "' 2>&1";
#else
    const std::string cmd = "fusermount3 -u '" + mp.string() + "' 2>&1 || umount '" + mp.string() + "' 2>&1";
#endif
    return std::system(cmd.c_str());
}

std::unique_ptr<fs::Reader> ext4Reader() {
    auto dev = loadSparseFixture("extfs/ext4.sparse");
    auto probed = fs::probe(dev);
    REQUIRE(probed);
    REQUIRE(*probed);
    auto reader = (*probed)->openReader();
    REQUIRE(reader);
    return std::move(*reader);
}

} // namespace

TEST_CASE("mount: run() returns when the user unmounts from outside (umount / fusermount3 -u), and running() turns false") {
    if (!stein::mount::Mount::available()) {
        skipOrFail("no usable mount backend on this machine; skipping");
        return;
    }
    LiveMount live(ext4Reader(), {});
    if (!live.skipWhy.empty()) {
        skipOrFail(live.skipWhy);
        return;
    }
    std::error_code ec;
    CHECK(std::filesystem::is_directory(live.mp / "lost+found", ec));
    // A second of serving, then the user's umount from another thread.
    int rc = -1;
    std::thread eject([&] {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        rc = unmountFromOutside(live.mp);
    });
    const auto t0 = std::chrono::steady_clock::now();
    const bool exited = live.waitForExit(std::chrono::seconds(10));
    const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
    eject.join();
    CHECK(rc == 0);
    CHECK_MESSAGE(exited, "run() still serving " << took.count() << " ms after the external unmount");
    CHECK(took < std::chrono::seconds(6));   // one second of serving plus the detection
    MESSAGE("run() returned " << took.count() << " ms after the test started (unmount at 1000 ms)");
    CHECK_FALSE(live.mount->running());
    CHECK(live.loopResult);
    // Nothing is mounted there any more: the directory is a plain, empty one again.
    CHECK_FALSE(std::filesystem::exists(live.mp / "lost+found", ec));
    // stop() after the fact is harmless and must not try to unmount somebody else's mount.
    live.mount->stop();
}

TEST_CASE("mount: LUKS2 (argon2id, 512-byte sectors; pbkdf2, 4096-byte sectors) -> ext2 -> mount, listed and stat'ed through the OS") {
    if (!stein::mount::Mount::available()) {
        skipOrFail("no usable mount backend on this machine; skipping");
        return;
    }
    for (const char* name : {"luks2", "luks2_pbkdf2"}) {
        const std::string fixture = name;
        CAPTURE(fixture);
        auto dev = loadSparseFixture("luks/" + fixture + ".sparse");
        REQUIRE(dev);
        auto luks = container::Luks::open(dev);
        REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
        CHECK(luks->info().sectorSize == (fixture == "luks2_pbkdf2" ? 4096u : 512u));
        auto payload = luks->openPayload("luks test passphrase", true);
        REQUIRE_MESSAGE(payload, (payload ? std::string() : payload.error().toString()));
        auto probed = fs::probe(*payload);
        REQUIRE(probed);
        REQUIRE(*probed);
        CHECK((*probed)->type() == fs::FsType::Ext2);
        const std::string label = (*probed)->info().label;
        CHECK(label == "inside_luks");
        auto reader = (*probed)->openReader();
        REQUIRE(reader);
        // The reader's own view of the root is what the OS must show through the mount.
        std::map<std::string, fs::Stat> want;
        {
            auto root = (*reader)->root();
            REQUIRE(root);
            auto entries = (*reader)->readdir(*root);
            REQUIRE(entries);
            for (const auto& e : *entries) {
                auto st = (*reader)->stat(e.inode);
                REQUIRE(st);
                want[e.name] = *st;
            }
        }
        REQUIRE(want.count("lost+found") == 1);
        stein::mount::MountOptions mo;
        mo.fsName = label;
        LiveMount live(std::move(*reader), mo);
        if (!live.skipWhy.empty()) {
            skipOrFail(live.skipWhy);
            return;
        }
        std::error_code ec;
        std::set<std::string> seen;
        for (const auto& e : std::filesystem::directory_iterator(live.mp, ec)) seen.insert(e.path().filename().string());
        CHECK_FALSE(ec);
        CHECK(seen.count("lost+found") == 1);
        for (const auto& [entry, st] : want) {
            CAPTURE(entry);
            CHECK(seen.count(entry) == 1);
        }
        CHECK(seen.size() == want.size());
        // stat through the kernel: a directory, read-only, the reader's size and mtime.
        struct stat sb {};
        REQUIRE(::stat((live.mp / "lost+found").c_str(), &sb) == 0);
        CHECK(S_ISDIR(sb.st_mode));
        CHECK((sb.st_mode & 0222) == 0);
        CHECK(static_cast<std::uint32_t>(sb.st_mode & 0777) == (want["lost+found"].mode & 0777u & ~0222u));
        CHECK(static_cast<std::uint64_t>(sb.st_size) == want["lost+found"].size);
        if (want["lost+found"].mtime) CHECK(static_cast<std::int64_t>(sb.st_mtime) == want["lost+found"].mtime);
        CHECK_FALSE(std::filesystem::exists(live.mp / "does-not-exist", ec));
        std::ofstream nope(live.mp / "new.txt");
        CHECK_FALSE(nope);
#if defined(__APPLE__)
        // The export carries the label, so Finder names the volume after it instead of "127.0.0.1:/".
        struct statfs sf {};
        REQUIRE(::statfs(live.mp.c_str(), &sf) == 0);
        CHECK(std::string(sf.f_fstypename) == "nfs");
        CHECK(std::string(sf.f_mntfromname) == "127.0.0.1:/" + label);
#endif
        live.mount->stop();
        live.loop.join();
        CHECK(live.loopResult);
    }
}

TEST_CASE("mount: the LUKS2 payload over NFS: lost+found listed and stat'ed through the OS, the volume named after the label, and run() returns after the user's umount") {
    if (!stein::mount::Mount::available()) {
        skipOrFail("no usable mount backend on this machine (macOS: /sbin/mount_nfs); skipping");
        return;
    }
    auto dev = loadSparseFixture("luks/luks2.sparse");
    REQUIRE(dev);
    auto luks = container::Luks::open(dev);
    REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
    // Read-only, so the payload comes with the read cache in front of the decryption: the NFS
    // threads and this thread share it, which is the arrangement the app's Browse + Mount makes.
    auto payload = luks->openPayload("luks test passphrase", true);
    REQUIRE_MESSAGE(payload, (payload ? std::string() : payload.error().toString()));
    auto probed = fs::probe(*payload);
    REQUIRE(probed);
    REQUIRE(*probed);
    REQUIRE((*probed)->type() == fs::FsType::Ext2);
    const std::string label = (*probed)->info().label;
    REQUIRE(label == "inside_luks");
    auto reader = (*probed)->openReader();
    REQUIRE(reader);
    fs::Stat wantLf;
    {
        auto root = (*reader)->root();
        REQUIRE(root);
        auto lf = (*reader)->lookup(*root, "lost+found");
        REQUIRE(lf);
        auto st = (*reader)->stat(*lf);
        REQUIRE(st);
        wantLf = *st;
    }
    stein::mount::MountOptions mo;
    mo.fsName = label;
    LiveMount live(std::move(*reader), mo);
    if (!live.skipWhy.empty()) {
        skipOrFail(live.skipWhy);
        return;
    }
    std::error_code ec;
    std::set<std::string> seen;
    for (const auto& e : std::filesystem::directory_iterator(live.mp, ec)) seen.insert(e.path().filename().string());
    CHECK_FALSE(ec);
    CHECK(seen == std::set<std::string>{"lost+found"});
    // stat through the kernel: a directory, no write bits anywhere, the reader's size and mtime.
    struct stat sb {};
    REQUIRE(::stat((live.mp / "lost+found").c_str(), &sb) == 0);
    CHECK(S_ISDIR(sb.st_mode));
    CHECK((sb.st_mode & 0222) == 0);
    CHECK(static_cast<std::uint32_t>(sb.st_mode & 0777) == (wantLf.mode & 0777u & ~0222u));
    CHECK(static_cast<std::uint64_t>(sb.st_size) == wantLf.size);
    if (wantLf.mtime) CHECK(static_cast<std::int64_t>(sb.st_mtime) == wantLf.mtime);
    std::set<std::string> inside;
    for (const auto& e : std::filesystem::directory_iterator(live.mp / "lost+found", ec)) inside.insert(e.path().filename().string());
    CHECK_FALSE(ec);
    CHECK(inside.empty());
    CHECK_FALSE(std::filesystem::exists(live.mp / "nothing-here", ec));
    std::ofstream nope(live.mp / "new.txt");
    CHECK_FALSE(nope);
#if defined(__APPLE__)
    struct statfs sf {};
    REQUIRE(::statfs(live.mp.c_str(), &sf) == 0);
    CHECK(std::string(sf.f_fstypename) == "nfs");
    CHECK(std::string(sf.f_mntfromname) == "127.0.0.1:/" + label);
    CHECK((sf.f_flags & MNT_RDONLY) != 0);
#endif
    // The user ejects from outside: run() must return on its own, and nothing of ours stays at the mountpoint.
    int rc = -1;
    std::thread eject([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        rc = unmountFromOutside(live.mp);
    });
    const auto t0 = std::chrono::steady_clock::now();
    const bool exited = live.waitForExit(std::chrono::seconds(10));
    const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
    eject.join();
    CHECK(rc == 0);
    CHECK_MESSAGE(exited, "run() still serving " << took.count() << " ms after the external unmount");
    CHECK(took < std::chrono::seconds(6));
    MESSAGE("LUKS2 payload over NFS: run() returned " << took.count() << " ms after the test started (umount at 500 ms)");
    CHECK_FALSE(live.mount->running());
    CHECK(live.loopResult);
    CHECK_FALSE(std::filesystem::exists(live.mp / "lost+found", ec));
#if defined(__APPLE__)
    REQUIRE(::statfs(live.mp.c_str(), &sf) == 0);
    CHECK(std::string(sf.f_fstypename) != "nfs");   // the directory is back on its own filesystem
#endif
    // The device chain outlives the mount: the payload is still readable in process.
    auto again = fs::probe(*payload);
    REQUIRE(again);
    REQUIRE(*again);
    CHECK((*again)->info().label == label);
    live.mount->stop();   // after the fact: harmless, and it must not unmount somebody else's mount
}
#endif   // !_WIN32

// ---------------------------------------------------------------- a real cryptsetup volume with files in it, through the OS

#if !defined(_WIN32)
#include "stein/core/strings.hpp"   // fromHex

namespace {
// tests/fixtures/luks/<name>.oracle.txt: "key=value" lines (passphrase, master_key, ...).
std::string luksOracle(const std::string& fixture, const std::string& key) {
    std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/luks/" + fixture + ".oracle.txt");
    std::string line;
    while (std::getline(in, line))
        if (line.rfind(key + "=", 0) == 0) return line.substr(key.size() + 1);
    return {};
}
// ext4_small.oracle.txt is `sha256sum` output: "<hex>  <path>" per line.
std::map<std::string, std::string> ext4SmallOracle() {
    std::map<std::string, std::string> m;
    std::ifstream in(std::string(STEIN_FIXTURE_DIR) + "/luks/ext4_small.oracle.txt");
    std::string line;
    while (std::getline(in, line))
        if (auto sep = line.find("  "); sep != std::string::npos) m[line.substr(sep + 2)] = line.substr(0, sep);
    return m;
}
std::string sha256HexOfFile(const std::filesystem::path& path, std::uint64_t& size) {
    std::ifstream in(path, std::ios::binary);
    REQUIRE_MESSAGE(in, path.string());
    auto hasher = Hasher::create(HashAlgorithm::Sha256);
    std::vector<std::byte> buf(64 * 1024);
    size = 0;
    while (in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size())) || in.gcount() > 0) {
        hasher->update(std::span<const std::byte>(buf.data(), static_cast<std::size_t>(in.gcount())));
        size += static_cast<std::uint64_t>(in.gcount());
    }
    return Hasher::hex(hasher->finish());
}
} // namespace

TEST_CASE("mount: a volume cryptsetup 2.8.4 made with its defaults (luks2_real: argon2id, 4096-byte sectors, ext4 with files) mounted over NFS: every file reads through the kernel with the oracle's sha256") {
    if (!stein::mount::Mount::available()) {
        skipOrFail("no usable mount backend on this machine (macOS: /sbin/mount_nfs); skipping");
        return;
    }
    auto dev = loadSparseFixture("luks/luks2_real.sparse");
    REQUIRE(dev);
    auto luks = container::Luks::open(dev);
    REQUIRE_MESSAGE(luks, (luks ? std::string() : luks.error().toString()));
    REQUIRE(luks->info().sectorSize == 4096);
    // The oracle's master key (what a passphrase unlock derives, minus the 1 GiB Argon2id): the
    // digest vouches for it, and the payload comes with the read cache the NFS threads share.
    auto hex = luksOracle("luks2_real", "master_key");
    auto keyBytes = fromHex(hex);
    REQUIRE(keyBytes);
    std::vector<std::uint8_t> masterKey(keyBytes->size());
    for (std::size_t i = 0; i < masterKey.size(); ++i) masterKey[i] = std::to_integer<std::uint8_t>((*keyBytes)[i]);
    auto payload = luks->openPayload(masterKey, true);
    REQUIRE_MESSAGE(payload, (payload ? std::string() : payload.error().toString()));
    auto probed = fs::probe(*payload);
    REQUIRE(probed);
    REQUIRE(*probed);
    REQUIRE((*probed)->type() == fs::FsType::Ext4);
    const std::string label = (*probed)->info().label;
    REQUIRE(label == "small_luks");
    auto reader = (*probed)->openReader();
    REQUIRE(reader);
    const auto files = ext4SmallOracle();
    REQUIRE(files.size() == 6);
    // What the reader says each file holds; the kernel must agree byte for byte.
    std::map<std::string, std::uint64_t> wantSize;
    for (const auto& [path, sha] : files) {
        auto inode = fs::resolvePath(**reader, path);
        REQUIRE_MESSAGE(inode, path);
        auto st = (*reader)->stat(*inode);
        REQUIRE(st);
        wantSize[path] = st->size;
    }
    stein::mount::MountOptions mo;
    mo.fsName = label;
    LiveMount live(std::move(*reader), mo);
    if (!live.skipWhy.empty()) {
        skipOrFail(live.skipWhy);
        return;
    }
    std::error_code ec;
    std::set<std::string> seen;
    for (const auto& e : std::filesystem::directory_iterator(live.mp, ec)) seen.insert(e.path().filename().string());
    CHECK_FALSE(ec);
    CHECK(seen == std::set<std::string>{"big.bin", "dir", "hello.txt", "lost+found"});
    std::set<std::string> nested;
    for (const auto& e : std::filesystem::directory_iterator(live.mp / "dir" / "nested", ec)) nested.insert(e.path().filename().string());
    CHECK_FALSE(ec);
    CHECK(nested == std::set<std::string>{"leaf.txt"});
    std::uint64_t total = 0;
    for (const auto& [path, sha] : files) {
        CAPTURE(path);
        std::uint64_t size = 0;
        CHECK(sha256HexOfFile(live.mp / path, size) == sha);
        CHECK(size == wantSize[path]);
        CHECK(std::filesystem::file_size(live.mp / path, ec) == wantSize[path]);
        total += size;
    }
    MESSAGE("luks2_real over NFS: " << files.size() << " files, " << total << " bytes read through the kernel and hashed");
    std::ofstream nope(live.mp / "dir" / "new.txt");
    CHECK_FALSE(nope);
#if defined(__APPLE__)
    struct statfs sf {};
    REQUIRE(::statfs(live.mp.c_str(), &sf) == 0);
    CHECK(std::string(sf.f_mntfromname) == "127.0.0.1:/" + label);
    CHECK((sf.f_flags & MNT_RDONLY) != 0);
#endif
    live.mount->stop();
    live.loop.join();
    CHECK(live.loopResult);
    CHECK_FALSE(std::filesystem::exists(live.mp / "hello.txt", ec));
}
#endif   // !_WIN32
