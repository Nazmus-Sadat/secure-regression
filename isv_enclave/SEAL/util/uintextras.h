#ifndef SEAL_UTIL_UINTEXTRAS_H
#define SEAL_UTIL_UINTEXTRAS_H

#include <stdint.h>
#include "mempool.h"

namespace seal
{
    namespace util
    {
        void exponentiate_uint(const uint64_t *operand, int operand_uint64_count, int exponent, int result_uint64_count, uint64_t *result, MemoryPool &pool);
    }
}

#endif // SEAL_UTIL_UINTEXTRAS_H
