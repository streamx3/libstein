// SPDX-License-Identifier: MIT
// LayoutTree: the parsed, annotated view of bytes. Every format module emits
// one; UIs render it as a tree next to a hex pane; the CLI prints it; tests
// diff it; dump/restore uses the range a subtree covers.
#pragma once

#include "stein/layout/spec.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace stein::layout {

enum class Validity : std::uint8_t { Ok, Info, Warning, Error };

std::string_view toString(Validity v);

struct Node {
    std::string name;
    std::uint64_t absOffset = 0;     // on the device the bytes came from
    std::uint64_t size = 0;
    FieldType type = FieldType::Bytes;
    bool isStruct = false;           // true for containers (no raw/value of its own)
    std::vector<std::byte> raw;      // field bytes (kept for fields up to 256 bytes)
    std::string value;               // canonical decoded text: "92", "EFI PART", GUID
    std::string pretty;              // human meaning: "EFI System Partition", "1.0", "a|b"
    std::string doc;
    Validity validity = Validity::Ok;
    std::string message;             // why validity is not Ok
    std::vector<Node> children;

    // Worst validity in the subtree.
    Validity overall() const;
    // Find a direct child by name (nullptr if absent).
    Node* child(std::string_view childName);
    const Node* child(std::string_view childName) const;
    void flag(Validity v, std::string why);    // raises validity, keeps the worst message
    Node& addChild(Node n);
    std::uint64_t endOffset() const { return absOffset + size; }

    // Indented text rendering, one line per node:
    // "  header_crc32      @0x010  4 B  crc32  0x9E3F1A2B  [FAIL] computed 0x...".
    std::string toText(int indent = 0, bool withDoc = false) const;
};

} // namespace stein::layout
