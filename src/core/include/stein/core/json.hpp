// SPDX-License-Identifier: MIT
// A small JSON value with a strict parser and a serializer. Used for image
// manifests, LUKS2 metadata, profiles. No templates beyond std containers.
#pragma once

#include "stein/core/error.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace stein::json {

enum class Type : std::uint8_t { Null, Bool, Number, String, Array, Object };

class Value {
public:
    using Array = std::vector<Value>;
    using Object = std::map<std::string, Value>;   // ordered keys: deterministic output

    Value() = default;                                  // null
    Value(std::nullptr_t) {}
    Value(bool b) : m_type(Type::Bool), m_bool(b) {}
    Value(int v) : m_type(Type::Number), m_number(static_cast<double>(v)), m_integer(v), m_isInteger(true) {}
    Value(std::int64_t v) : m_type(Type::Number), m_number(static_cast<double>(v)), m_integer(v), m_isInteger(true) {}
    Value(std::uint64_t v) : m_type(Type::Number), m_number(static_cast<double>(v)), m_integer(static_cast<std::int64_t>(v)), m_isInteger(true), m_isUnsigned(true) {}
    Value(double d) : m_type(Type::Number), m_number(d) {}
    Value(const char* s) : m_type(Type::String), m_string(s) {}
    Value(std::string s) : m_type(Type::String), m_string(std::move(s)) {}
    Value(std::string_view s) : m_type(Type::String), m_string(s) {}
    Value(Array a) : m_type(Type::Array), m_array(std::move(a)) {}
    Value(Object o) : m_type(Type::Object), m_object(std::move(o)) {}

    static Value array() { return Value(Array{}); }
    static Value object() { return Value(Object{}); }

    Type type() const { return m_type; }
    bool isNull() const { return m_type == Type::Null; }
    bool isBool() const { return m_type == Type::Bool; }
    bool isNumber() const { return m_type == Type::Number; }
    bool isString() const { return m_type == Type::String; }
    bool isArray() const { return m_type == Type::Array; }
    bool isObject() const { return m_type == Type::Object; }

    bool asBool(bool def = false) const { return isBool() ? m_bool : def; }
    double asDouble(double def = 0.0) const { return isNumber() ? m_number : def; }
    std::int64_t asInt(std::int64_t def = 0) const;
    std::uint64_t asUInt(std::uint64_t def = 0) const;
    const std::string& asString() const;                 // empty string when not a string
    const Array& asArray() const;                        // empty when not an array
    const Object& asObject() const;

    // Object access. get() returns a shared null for missing keys so chains like
    // v.get("a").get("b").asInt() are safe.
    const Value& get(std::string_view key) const;
    bool has(std::string_view key) const;
    Value& set(std::string key, Value v);                // makes this an object if null
    Value& push(Value v);                                // appends; makes this an array if null; returns *this for chaining
    std::size_t size() const;
    const Value& at(std::size_t i) const;

    std::string dump(int indent = 0) const;             // indent 0 = compact

    static Expected<Value> parse(std::string_view text);

private:
    Type m_type = Type::Null;
    bool m_bool = false;
    double m_number = 0.0;
    std::int64_t m_integer = 0;
    bool m_isInteger = false, m_isUnsigned = false;
    std::string m_string;
    Array m_array;
    Object m_object;
};

} // namespace stein::json
