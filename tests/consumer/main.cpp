// SPDX-License-Identifier: MIT
// Smoke test for the installed package: open an image through the public API and print its
// probe tree. Exits non-zero when nothing is recognised.
#include "stein/block/file_device.hpp"
#include "stein/probe/topology.hpp"

#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fputs("usage: stein_consumer <image>\n", stderr);
        return 2;
    }
    auto dev = stein::FileDevice::open(argv[1], stein::FileDevice::Mode::ReadOnly);
    if (!dev) {
        std::fprintf(stderr, "open: %s\n", dev.error().toString().c_str());
        return 1;
    }
    auto tree = stein::probe::probe(*dev);
    if (!tree) {
        std::fprintf(stderr, "probe: %s\n", tree.error().toString().c_str());
        return 1;
    }
    std::fputs(stein::probe::toText(*tree).c_str(), stdout);
    return tree->children.empty() && !tree->table && !tree->content ? 1 : 0;
}
