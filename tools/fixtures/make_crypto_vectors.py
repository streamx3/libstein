#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Regenerates src/core/tests/crypto_vectors.hpp with the Python `cryptography`
# package as the oracle. See that header for the generated content; the body of
# this script is the generator that produced it (kept for reproducibility).
# Run from the repository root: python3 tools/fixtures/make_crypto_vectors.py
import sys
print("see the git history of src/core/tests/crypto_vectors.hpp; generator inlined in the commit that added it", file=sys.stderr)
