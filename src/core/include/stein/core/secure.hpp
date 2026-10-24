// SPDX-License-Identifier: MIT
// Wiping key material. A plain memset just before a buffer is freed is a dead store the
// optimiser is allowed to drop, so passphrases, derived keys and the Argon2 working memory would
// stay in the heap after the unlock. secureZero() goes through the platform primitive that the
// compiler must not elide, or a volatile loop where there is none; WipeOnExit zeroes a buffer
// when its scope ends, whichever way it ends (return, early error return, exception).
#pragma once

#include <cstddef>
#include <iterator>

#if defined(__APPLE__)
// memset_s (C11 Annex K, in libSystem since 10.9). Darwin's <string.h> declares it only when
// __STDC_WANT_LIB_EXT1__ was defined before its *first* inclusion, which a header cannot
// guarantee, so it is declared here with Darwin's own types (errno_t is int, rsize_t is size_t).
extern "C" int memset_s(void* s, std::size_t smax, int c, std::size_t n);
#elif defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <string.h>   // explicit_bzero: glibc >= 2.25, musl >= 1.1.20 and the BSDs
#endif

namespace stein {

inline void secureZero(void* p, std::size_t n) {
    if (p == nullptr || n == 0) return;
#if defined(__APPLE__)
    memset_s(p, n, 0, n);
#elif defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    explicit_bzero(p, n);
#else
    // Windows and anything else: SecureZeroMemory would pull <windows.h> into every including
    // translation unit, and it is this same volatile loop inline (RtlSecureZeroMemory), which the
    // compiler must perform byte by byte.
    volatile unsigned char* v = static_cast<volatile unsigned char*>(p);
    while (n--) *v++ = 0;
#endif
}

// Zeroes a container's bytes (anything with std::data()/std::size(): vector, array, string) when
// the scope ends. The buffer the container holds *then* is wiped, so a vector that grew during
// the scope is covered, but a buffer it released by reallocating is not: size it up front.
template <class Container>
class WipeOnExit {
public:
    explicit WipeOnExit(Container& c) : m_c(c) {}
    ~WipeOnExit() { secureZero(std::data(m_c), std::size(m_c) * sizeof(*std::data(m_c))); }
    WipeOnExit(const WipeOnExit&) = delete;
    WipeOnExit& operator=(const WipeOnExit&) = delete;

private:
    Container& m_c;
};

// The same for a raw buffer (a unique_ptr<T[]>'s array, a struct) whose size is known up front.
class WipeBytesOnExit {
public:
    WipeBytesOnExit(void* p, std::size_t bytes) : m_p(p), m_n(bytes) {}
    ~WipeBytesOnExit() { secureZero(m_p, m_n); }
    WipeBytesOnExit(const WipeBytesOnExit&) = delete;
    WipeBytesOnExit& operator=(const WipeBytesOnExit&) = delete;

private:
    void* m_p;
    std::size_t m_n;
};

} // namespace stein
