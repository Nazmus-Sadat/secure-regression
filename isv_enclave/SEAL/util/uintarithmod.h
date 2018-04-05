#ifndef SEAL_UTIL_UINTARITHMOD_H
#define SEAL_UTIL_UINTARITHMOD_H

#include <stdint.h>
#include "mempool.h"
#include "modulus.h"

namespace seal
{
    namespace util
    {
        void modulo_uint_inplace(uint64_t *value, int value_uint64_count, const Modulus &modulus, MemoryPool &pool);

        void modulo_uint(const uint64_t *value, int value_uint64_count, const Modulus &modulus, uint64_t *result, MemoryPool &pool);

        void increment_uint_mod(const uint64_t *operand, const uint64_t *modulus, int uint64_count, uint64_t *result);

        void decrement_uint_mod(const uint64_t *operand, const uint64_t *modulus, int uint64_count, uint64_t *result);

        void negate_uint_mod(const uint64_t *operand, const uint64_t *modulus, int uint64_count, uint64_t *result);

        void div2_uint_mod(const uint64_t *operand, const uint64_t *modulus, int uint64_count, uint64_t *result);

        void add_uint_uint_mod(const uint64_t *operand1, const uint64_t *operand2, const uint64_t *modulus, int uint64_count, uint64_t *result);

        void sub_uint_uint_mod(const uint64_t *operand1, const uint64_t *operand2, const uint64_t *modulus, int uint64_count, uint64_t *result);

        void multiply_uint_uint_mod(const uint64_t *operand1, const uint64_t *operand2, const Modulus &modulus, uint64_t *result, MemoryPool &pool);

        void multiply_uint_uint_mod_inplace(const uint64_t *operand1, const uint64_t *operand2, const Modulus &modulus, uint64_t *result, MemoryPool &pool);

        bool try_invert_uint_mod(const uint64_t *operand, const uint64_t *modulus, int uint64_count, uint64_t *result, MemoryPool &pool);
    }
}

#endif // SEAL_UTIL_UINTARITHMOD_H
