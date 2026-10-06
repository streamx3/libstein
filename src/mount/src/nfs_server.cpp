// SPDX-License-Identifier: MIT
#include "stein/mount/nfs_server.hpp"

#include "stein/core/endian.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
using SocketT = SOCKET;
constexpr SocketT kBadSocket = INVALID_SOCKET;
static void closeSocket(SocketT s) { closesocket(s); }
static int pollOne(SocketT s, int ms) {
    WSAPOLLFD p{s, POLLRDNORM, 0};
    return WSAPoll(&p, 1, ms);
}
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
using SocketT = int;
constexpr SocketT kBadSocket = -1;
static void closeSocket(SocketT s) { ::close(s); }
static int pollOne(SocketT s, int ms) {
    pollfd p{s, POLLIN, 0};
    return ::poll(&p, 1, ms);
}
#endif

namespace stein::mount {

namespace {

// ---------------------------------------------------------------- XDR

class XdrWriter {
public:
    std::vector<std::byte> buf;
    void u32(std::uint32_t v) {
        std::byte b[4];
        storeBe32(b, v);
        buf.insert(buf.end(), b, b + 4);
    }
    void u64(std::uint64_t v) {
        std::byte b[8];
        storeBe64(b, v);
        buf.insert(buf.end(), b, b + 8);
    }
    void boolean(bool v) { u32(v ? 1 : 0); }
    void opaque(std::span<const std::byte> d) {
        u32(static_cast<std::uint32_t>(d.size()));
        buf.insert(buf.end(), d.begin(), d.end());
        while (buf.size() % 4) buf.push_back(std::byte{0});
    }
    void string(std::string_view s) { opaque(std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.data()), s.size())); }
};

class XdrReader {
public:
    explicit XdrReader(std::span<const std::byte> d) : m_d(d) {}
    bool ok() const { return !m_bad; }
    std::uint32_t u32() {
        if (m_pos + 4 > m_d.size()) {
            m_bad = true;
            return 0;
        }
        const std::uint32_t v = loadBe32(m_d.data() + m_pos);
        m_pos += 4;
        return v;
    }
    std::uint64_t u64() {
        const std::uint64_t hi = u32();
        return (hi << 32) | u32();
    }
    std::span<const std::byte> opaque(std::uint32_t maxLen = 1u << 20) {
        const std::uint32_t n = u32();
        if (m_bad || n > maxLen || m_pos + n > m_d.size()) {
            m_bad = true;
            return {};
        }
        auto s = m_d.subspan(m_pos, n);
        m_pos += (n + 3) & ~3u;
        return s;
    }
    std::string string(std::uint32_t maxLen = 4096) {
        auto s = opaque(maxLen);
        return std::string(reinterpret_cast<const char*>(s.data()), s.size());
    }
    void skipOpaque() { (void)opaque(1u << 20); }

private:
    std::span<const std::byte> m_d;
    std::size_t m_pos = 0;
    bool m_bad = false;
};

// ---------------------------------------------------------------- NFS constants

constexpr std::uint32_t kProgMount = 100005, kProgNfs = 100003, kVersion3 = 3;
constexpr std::uint32_t kNfs3Ok = 0, kNfs3ErrNoent = 2, kNfs3ErrIo = 5, kNfs3ErrAcces = 13, kNfs3ErrNotdir = 20, kNfs3ErrIsdir = 21, kNfs3ErrInval = 22,
                        kNfs3ErrRofs = 30, kNfs3ErrStale = 70, kNfs3ErrBadhandle = 10001, kNfs3ErrNotsupp = 10004;
constexpr std::uint32_t kAccessRead = 1, kAccessLookup = 2, kAccessExecute = 32;

std::uint32_t nfsType(fs::FileType t) {
    switch (t) {
    case fs::FileType::File: return 1;
    case fs::FileType::Directory: return 2;
    case fs::FileType::BlockDevice: return 3;
    case fs::FileType::CharDevice: return 4;
    case fs::FileType::Symlink: return 5;
    case fs::FileType::Socket: return 6;
    case fs::FileType::Fifo: return 7;
    default: return 1;
    }
}

std::uint32_t nfsError(const Error& e) {
    switch (e.category()) {
    case ErrorCategory::NotFound: return kNfs3ErrNoent;
    case ErrorCategory::Permission: return kNfs3ErrAcces;
    case ErrorCategory::InvalidArgument: return kNfs3ErrInval;
    case ErrorCategory::Unsupported: return kNfs3ErrNotsupp;
    default: return kNfs3ErrIo;
    }
}

} // namespace

// ---------------------------------------------------------------- server

struct NfsServer::Impl {
    std::unique_ptr<fs::Reader> reader;
    SocketT listenSock = kBadSocket;
    std::uint16_t port = 0;
    std::thread acceptThread;
    std::vector<std::thread> clients;
    std::mutex mutex;   // reader and caches
    std::atomic<bool> stopping{false};
    std::atomic<std::uint64_t> requests{0};
    std::map<std::uint64_t, std::vector<fs::DirEntry>> dirCache;
    std::uint64_t rootId = 0;
    std::vector<std::byte> readBuf;

    // ---- attributes

    std::uint32_t modeBits(const fs::Stat& st) const {
        std::uint32_t m = st.mode & 07777;
        if (m == 0) m = st.type == fs::FileType::Directory ? 0555 : 0444;
        m &= ~0222u;   // read-only export
        return m;
    }
    void writeFattr(XdrWriter& w, std::uint64_t id, const fs::Stat& st) const {
        w.u32(nfsType(st.type));
        w.u32(modeBits(st));
        w.u32(std::max<std::uint32_t>(1, st.nlink));
        w.u32(st.uid);
        w.u32(st.gid);
        w.u64(st.size);
        w.u64(st.allocatedBytes ? st.allocatedBytes : (st.size + 511) / 512 * 512);
        w.u32(0);
        w.u32(0);   // rdev
        w.u64(0x5354454Eu);   // fsid "STEN"
        w.u64(id);
        auto time = [&](std::int64_t t) {
            w.u32(static_cast<std::uint32_t>(t < 0 ? 0 : t));
            w.u32(0);
        };
        time(st.atime);
        time(st.mtime);
        time(st.ctime ? st.ctime : st.mtime);
    }
    // post_op_attr: attributes follow when the stat succeeds.
    void writePostOpAttr(XdrWriter& w, std::uint64_t id) {
        auto st = reader->stat(fs::Inode{id});
        if (!st) {
            w.boolean(false);
            return;
        }
        w.boolean(true);
        writeFattr(w, id, *st);
    }
    static void writeFh(XdrWriter& w, std::uint64_t id) {
        std::byte b[8];
        storeBe64(b, id);
        w.opaque(std::span<const std::byte>(b, 8));
    }
    static bool readFh(XdrReader& r, std::uint64_t& id) {
        auto fh = r.opaque(64);
        if (!r.ok() || fh.size() != 8) return false;
        id = loadBe64(fh.data());
        return true;
    }

    Expected<const std::vector<fs::DirEntry>*> entries(std::uint64_t dirId) {
        if (auto it = dirCache.find(dirId); it != dirCache.end()) return &it->second;
        auto e = reader->readdir(fs::Inode{dirId});
        if (!e) return fail(e.error());
        if (dirCache.size() > 4096) dirCache.clear();
        return &dirCache.emplace(dirId, std::move(*e)).first->second;
    }

    // ---- MOUNT program

    bool handleMount(std::uint32_t proc, XdrReader& args, XdrWriter& res) {
        switch (proc) {
        case 0: return true;   // NULL
        case 1: {              // MNT
            (void)args.string();
            res.u32(0);        // MNT3_OK
            writeFh(res, rootId);
            res.u32(2);        // auth flavors
            res.u32(1);        // AUTH_UNIX
            res.u32(0);        // AUTH_NULL
            return true;
        }
        case 2:   // DUMP: no entries
            res.boolean(false);
            return true;
        case 3:   // UMNT
        case 4:   // UMNTALL
            return true;
        case 5:   // EXPORT: one entry "/" open to everyone
            res.boolean(true);
            res.string("/");
            res.boolean(false);   // no groups
            res.boolean(false);   // end of list
            return true;
        default: return false;
        }
    }

    // ---- NFS program

    bool handleNfs(std::uint32_t proc, XdrReader& args, XdrWriter& res) {
        std::uint64_t id = 0;
        auto badHandle = [&]() {
            res.u32(kNfs3ErrBadhandle);
            return true;
        };
        switch (proc) {
        case 0: return true;   // NULL
        case 1: {              // GETATTR
            if (!readFh(args, id)) return badHandle();
            auto st = reader->stat(fs::Inode{id});
            if (!st) {
                res.u32(nfsError(st.error()));
                return true;
            }
            res.u32(kNfs3Ok);
            writeFattr(res, id, *st);
            return true;
        }
        case 3: {   // LOOKUP
            if (!readFh(args, id)) return badHandle();
            const std::string name = args.string(255);
            if (!args.ok()) return badHandle();
            auto dirSt = reader->stat(fs::Inode{id});
            if (!dirSt || dirSt->type != fs::FileType::Directory) {
                res.u32(kNfs3ErrNotdir);
                res.boolean(false);
                return true;
            }
            Expected<fs::Inode> found = fail(ErrorCategory::NotFound, "");
            if (name == "." || name.empty()) found = fs::Inode{id};
            else if (name == "..") found = fs::Inode{id};   // parents are not tracked: ".." of any directory is itself (the client resolves paths from the root)
            else found = reader->lookup(fs::Inode{id}, name);
            if (!found) {
                res.u32(nfsError(found.error()));
                writePostOpAttr(res, id);
                return true;
            }
            res.u32(kNfs3Ok);
            writeFh(res, found->id);
            writePostOpAttr(res, found->id);
            writePostOpAttr(res, id);
            return true;
        }
        case 4: {   // ACCESS
            if (!readFh(args, id)) return badHandle();
            const std::uint32_t want = args.u32();
            res.u32(kNfs3Ok);
            writePostOpAttr(res, id);
            res.u32(want & (kAccessRead | kAccessLookup | kAccessExecute));
            return true;
        }
        case 5: {   // READLINK
            if (!readFh(args, id)) return badHandle();
            auto target = reader->readlink(fs::Inode{id});
            if (!target) {
                res.u32(nfsError(target.error()));
                writePostOpAttr(res, id);
                return true;
            }
            res.u32(kNfs3Ok);
            writePostOpAttr(res, id);
            res.string(*target);
            return true;
        }
        case 6: {   // READ
            if (!readFh(args, id)) return badHandle();
            const std::uint64_t offset = args.u64();
            const std::uint32_t count = std::min<std::uint32_t>(args.u32(), 1u << 20);
            auto st = reader->stat(fs::Inode{id});
            if (!st) {
                res.u32(nfsError(st.error()));
                res.boolean(false);
                return true;
            }
            if (st->type == fs::FileType::Directory) {
                res.u32(kNfs3ErrIsdir);
                res.boolean(false);
                return true;
            }
            readBuf.resize(count);
            std::size_t got = 0;
            if (offset < st->size && count) {
                auto n = reader->read(fs::Inode{id}, offset, readBuf);
                if (!n) {
                    res.u32(nfsError(n.error()));
                    writePostOpAttr(res, id);
                    return true;
                }
                got = *n;
            }
            res.u32(kNfs3Ok);
            res.boolean(true);
            writeFattr(res, id, *st);
            res.u32(static_cast<std::uint32_t>(got));
            res.boolean(offset + got >= st->size);
            res.opaque(std::span<const std::byte>(readBuf).subspan(0, got));
            return true;
        }
        case 16:   // READDIR
        case 17: { // READDIRPLUS
            if (!readFh(args, id)) return badHandle();
            const std::uint64_t cookie = args.u64();
            args.u64();   // cookieverf
            std::uint32_t dircount = args.u32(), maxcount = dircount;
            if (proc == 17) maxcount = args.u32();
            auto dirSt = reader->stat(fs::Inode{id});
            if (!dirSt || dirSt->type != fs::FileType::Directory) {
                res.u32(kNfs3ErrNotdir);
                res.boolean(false);
                return true;
            }
            auto list = entries(id);
            if (!list) {
                res.u32(nfsError(list.error()));
                res.boolean(false);
                return true;
            }
            res.u32(kNfs3Ok);
            res.boolean(true);
            writeFattr(res, id, *dirSt);
            res.u64(0);   // cookieverf
            // Entries: cookie 1 ".", 2 "..", then 3.. for the listing.
            std::size_t bytes = 0;
            const std::size_t total = (*list)->size() + 2;
            std::uint64_t next = cookie;
            bool eof = true;
            for (std::uint64_t c = cookie + 1; c <= total; ++c) {
                const bool dot = c <= 2;
                const std::string name = c == 1 ? "." : c == 2 ? ".." : (**list)[static_cast<std::size_t>(c - 3)].name;
                const std::uint64_t entryId = dot ? id : (**list)[static_cast<std::size_t>(c - 3)].inode.id;
                const std::size_t cost = (proc == 17 ? 200 : 32) + name.size();
                if (bytes + cost > maxcount && c != cookie + 1) {
                    eof = false;
                    break;
                }
                bytes += cost;
                res.boolean(true);
                res.u64(entryId);
                res.string(name);
                res.u64(c);
                if (proc == 17) {
                    writePostOpAttr(res, entryId);
                    res.boolean(true);
                    writeFh(res, entryId);
                }
                next = c;
            }
            (void)next;
            res.boolean(false);
            res.boolean(eof);
            return true;
        }
        case 18: {   // FSSTAT
            if (!readFh(args, id)) return badHandle();
            res.u32(kNfs3Ok);
            writePostOpAttr(res, id);
            res.u64(0);
            res.u64(0);
            res.u64(0);   // tbytes fbytes abytes
            res.u64(0);
            res.u64(0);
            res.u64(0);   // tfiles ffiles afiles
            res.u32(0);   // invarsec
            return true;
        }
        case 19: {   // FSINFO
            if (!readFh(args, id)) return badHandle();
            res.u32(kNfs3Ok);
            writePostOpAttr(res, id);
            res.u32(1u << 20);   // rtmax
            res.u32(1u << 17);   // rtpref
            res.u32(4096);       // rtmult
            res.u32(4096);       // wtmax
            res.u32(4096);       // wtpref
            res.u32(4096);       // wtmult
            res.u32(1u << 16);   // dtpref
            res.u64(0x7FFFFFFFFFFFFFFFull);
            res.u32(1);
            res.u32(0);          // time_delta
            res.u32(0x1 | 0x2 | 0x8);   // FSF3_LINK | FSF3_SYMLINK | FSF3_HOMOGENEOUS
            return true;
        }
        case 20: {   // PATHCONF
            if (!readFh(args, id)) return badHandle();
            res.u32(kNfs3Ok);
            writePostOpAttr(res, id);
            res.u32(1);      // linkmax
            res.u32(255);    // name_max
            res.boolean(true);   // no_trunc
            res.boolean(true);   // chown_restricted
            res.boolean(!reader->caseSensitive());
            res.boolean(true);   // case_preserving
            return true;
        }
        case 2: case 7: case 8: case 9: case 10: case 11: case 12: case 13: case 14: case 15: case 21: {
            // SETATTR, WRITE, CREATE, MKDIR, SYMLINK, MKNOD, REMOVE, RMDIR, RENAME, LINK, COMMIT: read-only.
            res.u32(kNfs3ErrRofs);
            // wcc_data / post_op_attr placeholders: "no attributes" is valid for every one of them.
            res.boolean(false);
            res.boolean(false);
            return true;
        }
        default: return false;
        }
    }

    // ---- RPC

    // Returns the reply record (without the record mark); empty when the call is garbage.
    std::vector<std::byte> dispatch(std::span<const std::byte> record) {
        XdrReader r(record);
        const std::uint32_t xid = r.u32(), msgType = r.u32(), rpcVers = r.u32(), prog = r.u32(), vers = r.u32(), proc = r.u32();
        r.skipOpaque();   // cred: flavor + body
        r.u32();
        r.skipOpaque();   // verf
        r.u32();
        XdrWriter w;
        w.u32(xid);
        w.u32(1);   // REPLY
        if (!r.ok() || msgType != 0 || rpcVers != 2) {
            w.u32(1);   // MSG_DENIED
            w.u32(0);   // RPC_MISMATCH
            w.u32(2);
            w.u32(2);
            return std::move(w.buf);
        }
        w.u32(0);   // MSG_ACCEPTED
        w.u32(0);   // verf AUTH_NULL
        w.u32(0);
        if (prog != kProgMount && prog != kProgNfs) {
            w.u32(1);   // PROG_UNAVAIL
            return std::move(w.buf);
        }
        if (vers != kVersion3) {
            w.u32(2);   // PROG_MISMATCH
            w.u32(3);
            w.u32(3);
            return std::move(w.buf);
        }
        XdrWriter res;
        bool known;
        {
            std::lock_guard<std::mutex> lock(mutex);
            known = prog == kProgMount ? handleMount(proc, r, res) : handleNfs(proc, r, res);
        }
        if (!known) {
            w.u32(3);   // PROC_UNAVAIL
            return std::move(w.buf);
        }
        w.u32(0);   // SUCCESS
        w.buf.insert(w.buf.end(), res.buf.begin(), res.buf.end());
        ++requests;
        return std::move(w.buf);
    }

    static bool sendAll(SocketT s, std::span<const std::byte> d) {
        std::size_t done = 0;
        while (done < d.size()) {
            const auto n = ::send(s, reinterpret_cast<const char*>(d.data() + done), static_cast<int>(std::min<std::size_t>(d.size() - done, 1u << 20)), 0);
            if (n <= 0) return false;
            done += static_cast<std::size_t>(n);
        }
        return true;
    }

    void serveClient(SocketT s) {
        std::vector<std::byte> pending, record;
        std::byte chunk[65536];
        while (!stopping.load()) {
            const int pr = pollOne(s, 200);
            if (pr == 0) continue;
            if (pr < 0) break;
            const auto n = ::recv(s, reinterpret_cast<char*>(chunk), sizeof chunk, 0);
            if (n <= 0) break;
            pending.insert(pending.end(), chunk, chunk + n);
            // Record marking: 4-byte header, high bit = last fragment.
            for (;;) {
                if (pending.size() < 4) break;
                const std::uint32_t mark = loadBe32(pending.data());
                const std::uint32_t len = mark & 0x7FFFFFFFu;
                if (len > (8u << 20)) return;
                if (pending.size() < 4 + len) break;
                record.insert(record.end(), pending.begin() + 4, pending.begin() + 4 + len);
                pending.erase(pending.begin(), pending.begin() + 4 + len);
                if (!(mark & 0x80000000u)) continue;
                auto reply = dispatch(record);
                record.clear();
                if (reply.empty()) continue;
                std::byte head[4];
                storeBe32(head, 0x80000000u | static_cast<std::uint32_t>(reply.size()));
                if (!sendAll(s, std::span<const std::byte>(head, 4)) || !sendAll(s, reply)) return;
            }
        }
    }

    void acceptLoop() {
        while (!stopping.load()) {
            const int pr = pollOne(listenSock, 200);
            if (pr <= 0) continue;
            sockaddr_in peer{};
            socklen_t len = sizeof peer;
            const SocketT c = ::accept(listenSock, reinterpret_cast<sockaddr*>(&peer), &len);
            if (c == kBadSocket) continue;
            int one = 1;
            ::setsockopt(c, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof one);
            std::lock_guard<std::mutex> lock(mutex);
            clients.emplace_back([this, c] {
                serveClient(c);
                closeSocket(c);
            });
        }
    }
};

Expected<std::unique_ptr<NfsServer>> NfsServer::start(std::unique_ptr<fs::Reader> reader, const NfsServerOptions& options) {
    if (!reader) return fail(ErrorCategory::InvalidArgument, "no reader");
#if defined(_WIN32)
    static const int wsa = [] {
        WSADATA d;
        return WSAStartup(MAKEWORD(2, 2), &d);
    }();
    if (wsa != 0) return fail(ErrorCategory::Internal, "WSAStartup failed");
#endif
    std::unique_ptr<NfsServer> s(new NfsServer());
    s->m_impl = std::make_unique<Impl>();
    Impl& im = *s->m_impl;
    auto root = reader->root();
    if (!root) return fail(root.error());
    im.rootId = root->id;
    im.reader = std::move(reader);
    im.listenSock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (im.listenSock == kBadSocket) return fail(ErrorCategory::Io, "socket() failed");
    int one = 1;
    ::setsockopt(im.listenSock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof one);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(options.port);
    if (::inet_pton(AF_INET, options.bindAddress.c_str(), &addr.sin_addr) != 1) return fail(ErrorCategory::InvalidArgument, "bad bind address " + options.bindAddress);
    if (::bind(im.listenSock, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
        closeSocket(im.listenSock);
        im.listenSock = kBadSocket;
        return fail(ErrorCategory::Io, "cannot bind NFS server to " + options.bindAddress + ":" + std::to_string(options.port));
    }
    if (::listen(im.listenSock, 8) != 0) {
        closeSocket(im.listenSock);
        im.listenSock = kBadSocket;
        return fail(ErrorCategory::Io, "listen() failed");
    }
    sockaddr_in bound{};
    socklen_t blen = sizeof bound;
    ::getsockname(im.listenSock, reinterpret_cast<sockaddr*>(&bound), &blen);
    im.port = ntohs(bound.sin_port);
    im.acceptThread = std::thread([&im] { im.acceptLoop(); });
    return s;
}

std::uint16_t NfsServer::port() const { return m_impl ? m_impl->port : 0; }
std::uint64_t NfsServer::requests() const { return m_impl ? m_impl->requests.load() : 0; }

void NfsServer::stop() {
    if (!m_impl || m_impl->stopping.exchange(true)) return;
    if (m_impl->acceptThread.joinable()) m_impl->acceptThread.join();
    if (m_impl->listenSock != kBadSocket) {
        closeSocket(m_impl->listenSock);
        m_impl->listenSock = kBadSocket;
    }
    std::vector<std::thread> clients;
    {
        std::lock_guard<std::mutex> lock(m_impl->mutex);
        clients.swap(m_impl->clients);
    }
    for (auto& t : clients)
        if (t.joinable()) t.join();
}

NfsServer::~NfsServer() { stop(); }

// ---------------------------------------------------------------- single-file reader

namespace {
class SingleFileReader final : public fs::Reader {
public:
    SingleFileReader(std::shared_ptr<BlockDevice> device, std::string name) : m_device(std::move(device)), m_name(std::move(name)) {}
    Expected<fs::Inode> root() const override { return fs::Inode{1}; }
    Expected<fs::Inode> lookup(const fs::Inode& dir, std::string_view name) override {
        if (dir.id != 1) return fail(ErrorCategory::InvalidArgument, "not a directory");
        if (name == m_name) return fs::Inode{2};
        return fail(ErrorCategory::NotFound, "no entry named '" + std::string(name) + "'");
    }
    Expected<fs::Stat> stat(const fs::Inode& inode) override {
        fs::Stat st;
        if (inode.id == 1) {
            st.type = fs::FileType::Directory;
            st.mode = 0555;
            st.nlink = 2;
            return st;
        }
        if (inode.id != 2) return fail(ErrorCategory::NotFound, "no such inode");
        st.type = fs::FileType::File;
        st.mode = 0444;
        st.nlink = 1;
        st.size = m_device->size();
        st.allocatedBytes = m_device->size();
        return st;
    }
    Expected<std::vector<fs::DirEntry>> readdir(const fs::Inode& dir) override {
        if (dir.id != 1) return fail(ErrorCategory::InvalidArgument, "not a directory");
        return std::vector<fs::DirEntry>{fs::DirEntry{m_name, fs::Inode{2}, fs::FileType::File}};
    }
    Expected<std::size_t> read(const fs::Inode& file, std::uint64_t offset, std::span<std::byte> dst) override {
        if (file.id != 2) return fail(ErrorCategory::InvalidArgument, "not a file");
        if (offset >= m_device->size()) return 0;
        const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(dst.size(), m_device->size() - offset));
        if (auto r = m_device->readAt(offset, dst.subspan(0, n)); !r) return fail(r.error());
        return n;
    }
    Expected<std::string> readlink(const fs::Inode&) override { return fail(ErrorCategory::InvalidArgument, "not a symbolic link"); }
    bool caseSensitive() const override { return true; }

private:
    std::shared_ptr<BlockDevice> m_device;
    std::string m_name;
};
} // namespace

std::unique_ptr<fs::Reader> makeSingleFileReader(std::shared_ptr<BlockDevice> device, std::string name) {
    return std::make_unique<SingleFileReader>(std::move(device), std::move(name));
}

} // namespace stein::mount
