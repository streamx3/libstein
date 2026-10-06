// SPDX-License-Identifier: MIT
#include "stein_test.hpp"

#include "stein/core/crc32.hpp"
#include "stein/core/endian.hpp"
#include "stein/core/error.hpp"
#include "stein/core/guid.hpp"
#include "stein/core/hash.hpp"
#include "stein/core/progress.hpp"
#include "stein/core/report.hpp"
#include "stein/core/strings.hpp"
#include "stein/core/units.hpp"

#include <array>
#include <cstring>
#include <string>

using namespace stein;

using stein::test::bytesOf;

TEST_CASE("Error and Expected") {
    Expected<int> ok = 42;
    CHECK(ok.has_value());
    Expected<int> bad = fail(ErrorCategory::Io, "short read", 5);
    CHECK(!bad.has_value());
    CHECK(bad.error().category() == ErrorCategory::Io);
    CHECK(bad.error().toString() == "Io: short read (os error 5)");
    CHECK(Error().ok());
}

TEST_CASE("units: Region and alignment") {
    Region a{100, 50}, b{140, 10}, c{150, 10};
    CHECK(a.end() == 150);
    CHECK(a.overlaps(b));
    CHECK(!a.overlaps(c));
    CHECK(a.contains(b));
    CHECK(!a.contains(c));
    CHECK(alignUp(1, 4096) == 4096);
    CHECK(alignUp(4096, 4096) == 4096);
    CHECK(alignDown(4097, 4096) == 4096);
    CHECK(isAligned(8192, 4096));
    Geometry g{.sizeBytes = 2 * MiB, .logicalSectorSize = 512};
    CHECK(g.sectors() == 4096);
    CHECK(g.lbaToByte(2) == 1024);
}

TEST_CASE("units: formatSize") {
    CHECK(formatSize(0) == "0 B");
    CHECK(formatSize(512) == "512 B");
    CHECK(formatSize(1536) == "1.50 KiB");
    CHECK(formatSize(1610612736) == "1.50 GiB");
    CHECK(formatSize(1500000000, true) == "1.50 GB");
    CHECK(formatSizeExact(1610612736) == "1.50 GiB (1,610,612,736 bytes)");
}

TEST_CASE("endian") {
    std::array<std::byte, 8> buf{};
    storeLe32(buf.data(), 0x11223344u);
    CHECK(std::to_integer<int>(buf[0]) == 0x44);
    CHECK(loadLe32(buf.data()) == 0x11223344u);
    CHECK(loadBe32(buf.data()) == 0x44332211u);
    storeBe64(buf.data(), 0x0102030405060708ull);
    CHECK(std::to_integer<int>(buf[0]) == 0x01);
    CHECK(loadBe64(buf.data()) == 0x0102030405060708ull);
    CHECK(loadLe64(buf.data()) == 0x0807060504030201ull);
    std::uint16_t v = 0;
    CHECK(!loadLe16(std::span<const std::byte>(buf).subspan(7), 0, v));
    CHECK(loadLe16(buf, 6, v));
}

TEST_CASE("guid: parse/format/gpt byte order") {
    // EFI System Partition type GUID, as printed by UEFI and sgdisk.
    auto g = Uuid::parse("C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
    REQUIRE(g.has_value());
    CHECK(g->toString() == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
    CHECK(g->toString(false) == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
    // On disk in a GPT entry the first three groups are little-endian:
    std::array<std::byte, 16> disk{};
    g->toGptBytes(disk);
    const std::uint8_t expect[16] = {0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
                                     0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B};
    for (int i = 0; i < 16; ++i) CHECK(std::to_integer<int>(disk[i]) == expect[i]);
    CHECK(Uuid::fromGptBytes(disk) == *g);
    // RFC order round trip.
    std::array<std::byte, 16> rfc{};
    g->toRfcBytes(rfc);
    CHECK(std::to_integer<int>(rfc[0]) == 0xC1);
    CHECK(Uuid::fromRfcBytes(rfc) == *g);
    CHECK(Uuid::parse("{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}") == *g);
    CHECK(!Uuid::parse("c12a7328-f81f-11d2-ba4b-00a0c93ec93").has_value());
    CHECK(!Uuid::parse("c12a7328f81f11d2ba4b00a0c93ec93b").has_value());
    CHECK(Uuid().isNil());
    CHECK(!g->isNil());
}

TEST_CASE("crc32: known vectors") {
    CHECK(Crc32::compute(bytesOf("123456789")) == 0xCBF43926u);
    CHECK(Crc32::compute({}) == 0u);
    CHECK(Crc32c::compute(bytesOf("123456789")) == 0xE3069283u);
    Crc32 inc;
    inc.update(bytesOf("1234"));
    inc.update(bytesOf("56789"));
    CHECK(inc.value() == 0xCBF43926u);
}

TEST_CASE("hash: md5 and sha256 vectors") {
    CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Md5, {})) == "d41d8cd98f00b204e9800998ecf8427e");
    CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Md5, bytesOf("abc"))) == "900150983cd24fb0d6963f7d28e17f72");
    CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Md5, bytesOf("The quick brown fox jumps over the lazy dog"))) ==
          "9e107d9d372bb6826bd81d3542a419d6");
    CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, {})) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(Hasher::hex(Hasher::digest(HashAlgorithm::Sha256, bytesOf("abc"))) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    // Multi-block input, fed in odd-sized pieces.
    std::string million(1000000, 'a');
    auto h = Hasher::create(HashAlgorithm::Sha256);
    for (std::size_t i = 0; i < million.size(); i += 777)
        h->update(bytesOf(std::string_view(million).substr(i, 777)));
    CHECK(Hasher::hex(h->finish()) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    auto m = Hasher::create(HashAlgorithm::Md5);
    for (std::size_t i = 0; i < million.size(); i += 333)
        m->update(bytesOf(std::string_view(million).substr(i, 333)));
    CHECK(Hasher::hex(m->finish()) == "7707d6ae4e027c70eea2a935c2296f21");
}

TEST_CASE("strings: utf16le <-> utf8") {
    const std::uint8_t name[] = {'E', 0, 'F', 0, 'I', 0, 0, 0, 'x', 0};
    CHECK(utf16leToUtf8(std::as_bytes(std::span(name))) == "EFI");
    CHECK(utf16leToUtf8(std::as_bytes(std::span(name)), false) == std::string("EFI\0x", 5));
    std::array<std::byte, 72> field{};
    CHECK(utf8ToUtf16le("Ärger 😀", field));
    CHECK(utf16leToUtf8(field) == "Ärger 😀");
    CHECK(utf16Length("Ärger 😀") == 8);   // 6 BMP units + surrogate pair
    std::array<std::byte, 4> tiny{};
    CHECK(!utf8ToUtf16le("abc", tiny));   // truncation
    CHECK(isValidUtf8("Ärger"));
    CHECK(!isValidUtf8("\xC3"));
    CHECK(!isValidUtf8("\xC0\x80"));   // overlong NUL
}

TEST_CASE("strings: fields and helpers") {
    const std::uint8_t lbl[] = {'N', 'O', ' ', 'N', 'A', 'M', 'E', ' ', ' ', ' ', ' '};
    CHECK(asciiField(std::as_bytes(std::span(lbl))) == "NO NAME");
    std::array<std::byte, 11> f{};
    setAsciiField(f, "DATA", std::byte{' '});
    CHECK(asciiField(f) == "DATA");
    CHECK(std::to_integer<int>(f[10]) == ' ');
    CHECK(split("a,b,,c", ',') == std::vector<std::string>{"a", "b", "c"});
    CHECK(split("a,b,,c", ',', true) == std::vector<std::string>{"a", "b", "", "c"});
    CHECK(join({"x", "y"}, "-") == "x-y");
    CHECK(trim("  hi \n") == "hi");
    CHECK(toLower("AbC") == "abc");
    CHECK(startsWith("/dev/sda", "/dev/"));
    CHECK(endsWith("disk.img", ".img"));
    CHECK(iequals("GPT", "gpt"));
    CHECK(toHex(0x1A2Bu) == "0x1A2B");
    CHECK(toHex(5u, 4) == "0x0005");
    const std::uint8_t raw[] = {0xDE, 0xAD};
    CHECK(toHex(std::as_bytes(std::span(raw))) == "dead");
    auto dump = hexDump(bytesOf("EFI PART"), 512);
    CHECK(startsWith(dump, "00000200  45 46 49 20 50 41 52 54"));
    CHECK(dump.find("|EFI PART|") != std::string::npos);
}

TEST_CASE("progress and report") {
    struct Sink : ProgressSink {
        int updates = 0;
        ProgressSnapshot last;
        void onProgress(const ProgressSnapshot& s) override {
            ++updates;
            last = s;
        }
        void onMessage(std::string_view) override {}
    } sink;
    CancelToken cancel;
    Progress p(sink, &cancel);
    p.setPhase("Copying", 1000);
    p.advance(250);
    p.finishPhase();
    CHECK(sink.updates >= 2);
    CHECK(sink.last.done == 1000);
    CHECK(sink.last.phase == "Copying");
    CHECK(!p.isCancelled());
    cancel.cancel();
    CHECK(p.isCancelled());

    Report r("Restore image");
    r.start();
    auto& c = r.addChild("Write GPT");
    c.start();
    c.addDetail("sectors", "34");
    c.finish(ReportStatus::Success);
    r.addLine("done");
    r.finish(ReportStatus::Success);
    auto text = r.toText();
    CHECK(text.find("[OK] Restore image") == 0);
    CHECK(text.find("  [OK] Write GPT") != std::string::npos);
    CHECK(text.find("sectors: 34") != std::string::npos);
}
