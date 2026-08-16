#include "SIMDUtils.h"
#include <intrin.h>
#include <immintrin.h>

bool HasNullByte(const char* data, size_t len) {
    const char* p   = data;
    const char* end = data + len;

#if defined(__AVX2__)
    const __m256i z256 = _mm256_setzero_si256();
    for (; p + 32 <= end; p += 32) {
        __m256i v = _mm256_loadu_si256((const __m256i*)p);
        if (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, z256))) return true;
    }
#endif
    const __m128i z128 = _mm_setzero_si128();
    for (; p + 16 <= end; p += 16) {
        __m128i v = _mm_loadu_si128((const __m128i*)p);
        if (_mm_movemask_epi8(_mm_cmpeq_epi8(v, z128))) return true;
    }
    for (; p < end; ++p)
        if (!*p) return true;
    return false;
}
