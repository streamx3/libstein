// SPDX-License-Identifier: MIT
#include "stein/layout/node.hpp"

#include <cstdio>

namespace stein::layout {

std::string_view toString(Validity v) {
    switch (v) {
    case Validity::Ok: return "ok";
    case Validity::Info: return "info";
    case Validity::Warning: return "WARN";
    case Validity::Error: return "FAIL";
    }
    return "?";
}

Validity Node::overall() const {
    Validity worst = validity;
    for (const auto& c : children) {
        Validity v = c.overall();
        if (v > worst) worst = v;
    }
    return worst;
}

Node* Node::child(std::string_view childName) {
    for (auto& c : children)
        if (c.name == childName) return &c;
    return nullptr;
}

const Node* Node::child(std::string_view childName) const {
    for (const auto& c : children)
        if (c.name == childName) return &c;
    return nullptr;
}

void Node::flag(Validity v, std::string why) {
    if (v >= validity) {
        validity = v;
        message = std::move(why);
    }
}

Node& Node::addChild(Node n) {
    children.push_back(std::move(n));
    return children.back();
}

std::string Node::toText(int indent, bool withDoc) const {
    std::string pad(static_cast<std::size_t>(indent) * 2, ' ');
    char head[160];
    std::string out;
    if (isStruct) {
        std::snprintf(head, sizeof head, "%s%s @0x%llX (%llu B)", pad.c_str(), name.c_str(),
                      static_cast<unsigned long long>(absOffset), static_cast<unsigned long long>(size));
        out += head;
        if (validity != Validity::Ok) out += " [" + std::string(stein::layout::toString(validity)) + "] " + message;
    } else {
        std::snprintf(head, sizeof head, "%s%-24s @0x%-6llX %4llu B  %-7s %s", pad.c_str(), name.c_str(),
                      static_cast<unsigned long long>(absOffset), static_cast<unsigned long long>(size),
                      std::string(stein::layout::toString(type)).c_str(), value.c_str());
        out += head;
        if (!pretty.empty() && pretty != value) out += "  (" + pretty + ")";
        if (validity != Validity::Ok) out += "  [" + std::string(stein::layout::toString(validity)) + "] " + message;
    }
    if (withDoc && !doc.empty()) out += "  -- " + doc;
    out += "\n";
    for (const auto& c : children) out += c.toText(indent + 1, withDoc);
    return out;
}

} // namespace stein::layout
