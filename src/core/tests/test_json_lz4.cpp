// SPDX-License-Identifier: MIT
#include "stein_test.hpp"

#include "stein/core/json.hpp"
#include "stein/core/lz4.hpp"

#include <random>
#include <string>

using namespace stein;
using stein::test::bytesOf;

TEST_CASE("json: parse and dump round trip") {
    auto v = json::Value::parse(R"({"name":"stein","size":16777216,"neg":-5,"pi":3.5,"ok":true,"nil":null,
                                   "list":[1,2,"xé😀"],"obj":{"a":{"b":[]}}})");
    REQUIRE(v);
    CHECK(v->get("name").asString() == "stein");
    CHECK(v->get("size").asUInt() == 16777216u);
    CHECK(v->get("neg").asInt() == -5);
    CHECK(v->get("pi").asDouble() == 3.5);
    CHECK(v->get("ok").asBool());
    CHECK(v->get("nil").isNull());
    CHECK(v->get("missing").get("deeper").isNull());
    CHECK(v->get("list").size() == 3);
    CHECK(v->get("list").at(2).asString() == "x\xC3\xA9\xF0\x9F\x98\x80");
    CHECK(v->get("obj").get("a").get("b").isArray());
    const std::string compact = v->dump();
    auto again = json::Value::parse(compact);
    REQUIRE(again);
    CHECK(again->dump() == compact);
    CHECK(compact.find("\"size\":16777216") != std::string::npos);
    CHECK(compact.find("\"neg\":-5") != std::string::npos);
    const std::string pretty = v->dump(2);
    CHECK(pretty.find("\n  \"list\": [\n    1,") != std::string::npos);
}

TEST_CASE("json: builder API and errors") {
    json::Value m;
    m.set("version", 1);
    m.set("uuid", "abc");
    m.set("chunks", json::Value::array());
    m.set("source", json::Value::object());
    auto& list = m.set("list", json::Value::array());
    list.push(1).push(2);
    CHECK(m.dump() == R"({"chunks":[],"list":[1,2],"source":{},"uuid":"abc","version":1})");
    CHECK(!json::Value::parse("{"));
    CHECK(!json::Value::parse("[1,]"));
    CHECK(!json::Value::parse("\"unterminated"));
    CHECK(!json::Value::parse("01"));
    CHECK(!json::Value::parse("{\"a\":1} x"));
    CHECK(json::Value::parse("  7 ")->asInt() == 7);
    CHECK(json::Value::parse("\"a\\\"b\"")->asString() == "a\"b");
    CHECK(json::Value::parse("18446744073709551615")->asUInt() == 18446744073709551615ull);
}

TEST_CASE("lz4: round trips and known block") {
    // Known vector: "aaaaaaaaaaaaaaaaaaaaaaaa" (24 x 'a') -> literal 'a', match offset 1.
    std::string a(24, 'a');
    auto c = lz4::compress(bytesOf(a));
    CHECK(c.size() < a.size());
    auto d = lz4::decompress(c, a.size());
    REQUIRE(d);
    CHECK(std::string(reinterpret_cast<const char*>(d->data()), d->size()) == a);
    // A hand-encoded block for the same input: token 0x1E = 1 literal + match length 14+4 = 18
    // at offset 1, then the mandatory final literal-only sequence of 5 bytes.
    const std::uint8_t ref[] = {0x1E, 'a', 0x01, 0x00, 0x50, 'a', 'a', 'a', 'a', 'a'};
    auto dref = lz4::decompress(std::as_bytes(std::span(ref)), 24);
    REQUIRE(dref);
    CHECK(std::string(reinterpret_cast<const char*>(dref->data()), 24) == a);

    std::mt19937 rng(42);
    for (std::size_t size : {std::size_t{0}, std::size_t{1}, std::size_t{5}, std::size_t{12}, std::size_t{13}, std::size_t{100}, std::size_t{4096}, std::size_t{70000}, std::size_t{1u << 20}}) {
        std::vector<std::byte> in(size);
        // mixed content: repeated phrases, random bytes, zero runs
        for (std::size_t i = 0; i < size; ++i) {
            if ((i / 977) % 3 == 0) in[i] = std::byte(static_cast<unsigned char>("stein image chunk "[i % 18]));
            else if ((i / 977) % 3 == 1) in[i] = std::byte(static_cast<unsigned char>(rng()));
            else in[i] = std::byte{0};
        }
        auto comp = lz4::compress(in);
        INFO("size ", size, " compressed ", comp.size());
        REQUIRE(comp.size() <= lz4::compressBound(size));
        auto back = lz4::decompress(comp, size);
        REQUIRE(back);
        CHECK(*back == in);
        if (size >= 4096) CHECK(comp.size() < size);   // our mix is compressible
    }
    // Incompressible random data must still round-trip and stay within bound.
    std::vector<std::byte> rnd(65536);
    for (auto& b : rnd) b = std::byte(static_cast<unsigned char>(rng()));
    auto cr = lz4::compress(rnd);
    CHECK(cr.size() <= lz4::compressBound(rnd.size()));
    CHECK(*lz4::decompress(cr, rnd.size()) == rnd);
}

TEST_CASE("lz4: malformed input is rejected safely") {
    std::vector<std::byte> out(100);
    const std::uint8_t trunc[] = {0xF0};
    CHECK(!lz4::decompress(std::as_bytes(std::span(trunc)), out));
    const std::uint8_t badOffset[] = {0x10, 'a', 0x05, 0x00};   // offset 5 with only 1 byte written
    CHECK(!lz4::decompress(std::as_bytes(std::span(badOffset)), out));
    const std::uint8_t overflow[] = {0x10, 'a', 0x01, 0x00};   // 4+ bytes match into a 2-byte output
    std::vector<std::byte> small(2);
    CHECK(!lz4::decompress(std::as_bytes(std::span(overflow)), small));
    const std::uint8_t sizeMismatch[] = {0x20, 'a', 'b'};
    std::vector<std::byte> three(3);
    CHECK(!lz4::decompress(std::as_bytes(std::span(sizeMismatch)), three));
}
