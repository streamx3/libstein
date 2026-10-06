// SPDX-License-Identifier: MIT
#include "stein/core/json.hpp"

#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace stein::json {

namespace {
const Value& nullValue() {
    static const Value v;
    return v;
}
const std::string& emptyString() {
    static const std::string s;
    return s;
}
const Value::Array& emptyArray() {
    static const Value::Array a;
    return a;
}
const Value::Object& emptyObject() {
    static const Value::Object o;
    return o;
}
} // namespace

std::int64_t Value::asInt(std::int64_t def) const {
    if (!isNumber()) return def;
    if (m_isInteger) return m_integer;
    return static_cast<std::int64_t>(m_number);
}

std::uint64_t Value::asUInt(std::uint64_t def) const {
    if (!isNumber()) return def;
    if (m_isInteger) return m_isUnsigned ? static_cast<std::uint64_t>(m_integer) : (m_integer < 0 ? def : static_cast<std::uint64_t>(m_integer));
    return m_number < 0 ? def : static_cast<std::uint64_t>(m_number);
}

const std::string& Value::asString() const { return isString() ? m_string : emptyString(); }
const Value::Array& Value::asArray() const { return isArray() ? m_array : emptyArray(); }
const Value::Object& Value::asObject() const { return isObject() ? m_object : emptyObject(); }

const Value& Value::get(std::string_view key) const {
    if (!isObject()) return nullValue();
    auto it = m_object.find(std::string(key));
    return it == m_object.end() ? nullValue() : it->second;
}

bool Value::has(std::string_view key) const { return isObject() && m_object.count(std::string(key)) > 0; }

Value& Value::set(std::string key, Value v) {
    if (!isObject()) {
        *this = Value(Object{});
    }
    return m_object[std::move(key)] = std::move(v);
}

Value& Value::push(Value v) {
    if (!isArray()) *this = Value(Array{});
    m_array.push_back(std::move(v));
    return *this;
}

std::size_t Value::size() const {
    if (isArray()) return m_array.size();
    if (isObject()) return m_object.size();
    return 0;
}

const Value& Value::at(std::size_t i) const { return isArray() && i < m_array.size() ? m_array[i] : nullValue(); }

// ----------------------------------------------------------------------------- dump

namespace {

void dumpString(const std::string& s, std::string& out) {
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof buf, "\\u%04x", c);
                out += buf;
            } else {
                out.push_back(static_cast<char>(c));
            }
        }
    }
    out.push_back('"');
}

void dumpValue(const Value& v, int indent, int depth, std::string& out);

void newline(int indent, int depth, std::string& out) {
    if (indent <= 0) return;
    out.push_back('\n');
    out.append(static_cast<std::size_t>(indent * depth), ' ');
}

void dumpValue(const Value& v, int indent, int depth, std::string& out) {
    switch (v.type()) {
    case Type::Null: out += "null"; break;
    case Type::Bool: out += v.asBool() ? "true" : "false"; break;
    case Type::Number: {
        const double d = v.asDouble();
        if (std::floor(d) == d && std::fabs(d) < 9.2e18) {
            // integers print as integers (unsigned when it was stored unsigned)
            if (v.asInt() < 0) out += std::to_string(v.asInt());
            else out += std::to_string(v.asUInt());
        } else {
            char buf[32];
            std::snprintf(buf, sizeof buf, "%.17g", d);
            out += buf;
        }
        break;
    }
    case Type::String: dumpString(v.asString(), out); break;
    case Type::Array: {
        const auto& a = v.asArray();
        if (a.empty()) {
            out += "[]";
            break;
        }
        out.push_back('[');
        for (std::size_t i = 0; i < a.size(); ++i) {
            if (i) out.push_back(',');
            newline(indent, depth + 1, out);
            dumpValue(a[i], indent, depth + 1, out);
        }
        newline(indent, depth, out);
        out.push_back(']');
        break;
    }
    case Type::Object: {
        const auto& o = v.asObject();
        if (o.empty()) {
            out += "{}";
            break;
        }
        out.push_back('{');
        bool first = true;
        for (const auto& [k, val] : o) {
            if (!first) out.push_back(',');
            first = false;
            newline(indent, depth + 1, out);
            dumpString(k, out);
            out += indent > 0 ? ": " : ":";
            dumpValue(val, indent, depth + 1, out);
        }
        newline(indent, depth, out);
        out.push_back('}');
        break;
    }
    }
}

} // namespace

std::string Value::dump(int indent) const {
    std::string out;
    dumpValue(*this, indent, 0, out);
    return out;
}

// ----------------------------------------------------------------------------- parse

namespace {

class Parser {
public:
    explicit Parser(std::string_view t) : m_text(t) {}

    Expected<Value> parseDocument() {
        skipWs();
        auto v = parseValue(0);
        if (!v) return v;
        skipWs();
        if (m_pos != m_text.size()) return error("trailing characters");
        return v;
    }

private:
    std::unexpected<Error> error(const std::string& what) {
        return fail(ErrorCategory::InvalidFormat, "JSON: " + what + " at offset " + std::to_string(m_pos));
    }
    void skipWs() {
        while (m_pos < m_text.size() && (m_text[m_pos] == ' ' || m_text[m_pos] == '\t' || m_text[m_pos] == '\n' || m_text[m_pos] == '\r')) ++m_pos;
    }
    bool consume(char c) {
        if (m_pos < m_text.size() && m_text[m_pos] == c) {
            ++m_pos;
            return true;
        }
        return false;
    }
    bool consumeWord(std::string_view w) {
        if (m_text.substr(m_pos, w.size()) == w) {
            m_pos += w.size();
            return true;
        }
        return false;
    }

    Expected<Value> parseValue(int depth) {
        if (depth > 256) return error("nesting too deep");
        if (m_pos >= m_text.size()) return error("unexpected end");
        const char c = m_text[m_pos];
        if (c == '{') return parseObject(depth);
        if (c == '[') return parseArray(depth);
        if (c == '"') {
            auto s = parseString();
            if (!s) return fail(s.error());
            return Value(std::move(*s));
        }
        if (consumeWord("true")) return Value(true);
        if (consumeWord("false")) return Value(false);
        if (consumeWord("null")) return Value(nullptr);
        if (c == '-' || (c >= '0' && c <= '9')) return parseNumber();
        return error(std::string("unexpected character '") + c + "'");
    }

    Expected<Value> parseNumber() {
        const std::size_t start = m_pos;
        if (consume('-')) {}
        if (m_pos >= m_text.size() || !(m_text[m_pos] >= '0' && m_text[m_pos] <= '9')) return error("bad number");
        if (m_text[m_pos] == '0') ++m_pos;
        else while (m_pos < m_text.size() && m_text[m_pos] >= '0' && m_text[m_pos] <= '9') ++m_pos;
        bool isFloat = false;
        if (consume('.')) {
            isFloat = true;
            if (m_pos >= m_text.size() || !(m_text[m_pos] >= '0' && m_text[m_pos] <= '9')) return error("bad fraction");
            while (m_pos < m_text.size() && m_text[m_pos] >= '0' && m_text[m_pos] <= '9') ++m_pos;
        }
        if (m_pos < m_text.size() && (m_text[m_pos] == 'e' || m_text[m_pos] == 'E')) {
            isFloat = true;
            ++m_pos;
            if (m_pos < m_text.size() && (m_text[m_pos] == '+' || m_text[m_pos] == '-')) ++m_pos;
            if (m_pos >= m_text.size() || !(m_text[m_pos] >= '0' && m_text[m_pos] <= '9')) return error("bad exponent");
            while (m_pos < m_text.size() && m_text[m_pos] >= '0' && m_text[m_pos] <= '9') ++m_pos;
        }
        const std::string tok(m_text.substr(start, m_pos - start));
        if (!isFloat) {
            errno = 0;
            if (tok[0] == '-') {
                const long long v = std::strtoll(tok.c_str(), nullptr, 10);
                if (errno != ERANGE) return Value(static_cast<std::int64_t>(v));
            } else {
                const unsigned long long v = std::strtoull(tok.c_str(), nullptr, 10);
                if (errno != ERANGE) return Value(static_cast<std::uint64_t>(v));
            }
        }
        return Value(std::strtod(tok.c_str(), nullptr));
    }

    Expected<std::string> parseString() {
        if (!consume('"')) return error("expected string");
        std::string out;
        while (true) {
            if (m_pos >= m_text.size()) return error("unterminated string");
            char c = m_text[m_pos++];
            if (c == '"') return out;
            if (static_cast<unsigned char>(c) < 0x20) return error("control character in string");
            if (c != '\\') {
                out.push_back(c);
                continue;
            }
            if (m_pos >= m_text.size()) return error("bad escape");
            c = m_text[m_pos++];
            switch (c) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                auto hex4 = [&](std::uint32_t& cp) -> bool {
                    if (m_pos + 4 > m_text.size()) return false;
                    cp = 0;
                    for (int i = 0; i < 4; ++i) {
                        const char h = m_text[m_pos++];
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp |= static_cast<std::uint32_t>(h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= static_cast<std::uint32_t>(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= static_cast<std::uint32_t>(h - 'A' + 10);
                        else return false;
                    }
                    return true;
                };
                std::uint32_t cp;
                if (!hex4(cp)) return error("bad \\u escape");
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    std::uint32_t lo;
                    if (!consumeWord("\\u") || !hex4(lo) || lo < 0xDC00 || lo > 0xDFFF) return error("bad surrogate pair");
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                }
                if (cp < 0x80) out.push_back(static_cast<char>(cp));
                else if (cp < 0x800) {
                    out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                } else if (cp < 0x10000) {
                    out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                } else {
                    out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
                    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                }
                break;
            }
            default: return error("bad escape");
            }
        }
    }

    Expected<Value> parseArray(int depth) {
        consume('[');
        Value::Array arr;
        skipWs();
        if (consume(']')) return Value(std::move(arr));
        while (true) {
            skipWs();
            auto v = parseValue(depth + 1);
            if (!v) return v;
            arr.push_back(std::move(*v));
            skipWs();
            if (consume(',')) continue;
            if (consume(']')) return Value(std::move(arr));
            return error("expected ',' or ']'");
        }
    }

    Expected<Value> parseObject(int depth) {
        consume('{');
        Value::Object obj;
        skipWs();
        if (consume('}')) return Value(std::move(obj));
        while (true) {
            skipWs();
            auto k = parseString();
            if (!k) return fail(k.error());
            skipWs();
            if (!consume(':')) return error("expected ':'");
            skipWs();
            auto v = parseValue(depth + 1);
            if (!v) return v;
            obj[std::move(*k)] = std::move(*v);
            skipWs();
            if (consume(',')) continue;
            if (consume('}')) return Value(std::move(obj));
            return error("expected ',' or '}'");
        }
    }

    std::string_view m_text;
    std::size_t m_pos = 0;
};

} // namespace

Expected<Value> Value::parse(std::string_view text) { return Parser(text).parseDocument(); }

} // namespace stein::json
