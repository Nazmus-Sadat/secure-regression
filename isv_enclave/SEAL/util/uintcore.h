#ifndef SEAL_UTIL_UINTCORE_H
#define SEAL_UTIL_UINTCORE_H

#include <stdint.h>
#include <stdexcept>
#include "common.h"
#include "mempool.h"

namespace seal
{
    namespace util
    {
        inline Pointer allocate_uint(int uint64_count, MemoryPool &pool)
        {
#ifdef _DEBUG
            if (uint64_count < 0)
            {
                throw std::invalid_argument("uint64_count");
            }
#endif
            return pool.get_for_uint64_count(uint64_count);
        }

        inline void set_zero_uint(int uint64_count, uint64_t* result)
        {
#ifdef _DEBUG
            if (uint64_count < 0)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (result == nullptr && uint64_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            for (int i = 0; i < uint64_count; i++)
            {
                *result++ = 0;
            }
        }

        inline Pointer allocate_zero_uint(int uint64_count, MemoryPool &pool)
        {
#ifdef _DEBUG
            if (uint64_count < 0)
            {
                throw std::invalid_argument("uint64_count");
            }
#endif
            Pointer allocated = allocate_uint(uint64_count, pool);
            set_zero_uint(uint64_count, allocated.get());
            return allocated;
        }

        inline void set_uint(uint64_t value, int uint64_count, uint64_t* result)
        {
#ifdef _DEBUG
            if (uint64_count <= 0)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (result == nullptr)
            {
                throw std::invalid_argument("result");
            }
#endif
            *result++ = value;
            for (int i = 1; i < uint64_count; i++)
            {
                *result++ = 0;
            }
        }

        inline void set_uint_uint(const uint64_t *value, int uint64_count, uint64_t* result)
        {
#ifdef _DEBUG
            if (value == nullptr && uint64_count > 0)
            {
                throw std::invalid_argument("value");
            }
            if (uint64_count < 0)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (result == nullptr && uint64_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            if (value == result)
            {
                // Fast path to handle self assignment.
                return;
            }
            for (int i = 0; i < uint64_count; i++)
            {
                *result++ = *value++;
            }
        }

        inline void set_uint_uint(const uint64_t *value, int value_uint64_count, int result_uint64_count, uint64_t* result)
        {
#ifdef _DEBUG
            if (value == nullptr && value_uint64_count > 0)
            {
                throw std::invalid_argument("value");
            }
            if (value_uint64_count < 0)
            {
                throw std::invalid_argument("value_uint64_count");
            }
            if (result_uint64_count < 0)
            {
                throw std::invalid_argument("result_uint64_count");
            }
            if (result == nullptr && result_uint64_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            if (value == result)
            {
                // Fast path to handle self assignment.
                result += value_uint64_count;
                for (int i = value_uint64_count; i < result_uint64_count; ++i)
                {
                    *result++ = 0;
                }
                return;
            }
            for (int i = 0; i < result_uint64_count; ++i)
            {
                uint64_t curr_value = i < value_uint64_count ? *value++ : 0;
                *result++ = curr_value;
            }
        }

        inline bool is_zero_uint(const uint64_t *value, int uint64_count)
        {
#ifdef _DEBUG
            if (value == nullptr && uint64_count > 0)
            {
                throw std::invalid_argument("value");
            }
            if (uint64_count < 0)
            {
                throw std::invalid_argument("uint64_count");
            }
#endif
            for (int i = 0; i < uint64_count; ++i)
            {
                if (*value++ != 0)
                {
                    return false;
                }
            }
            return true;
        }

        inline bool is_equal_uint(const uint64_t *value, int uint64_count, uint64_t scalar)
        {
#ifdef _DEBUG
            if (value == nullptr)
            {
                throw std::invalid_argument("value");
            }
            if (uint64_count <= 0)
            {
                throw std::invalid_argument("uint64_count");
            }
#endif
            if (*value++ != scalar)
            {
                return false;
            }
            for (int i = 1; i < uint64_count; ++i)
            {
                if (*value++ != 0)
                {
                    return false;
                }
            }
            return true;
        }

        inline bool is_high_bit_set_uint(const uint64_t *value, int uint64_count)
        {
#ifdef _DEBUG
            if (value == nullptr)
            {
                throw std::invalid_argument("value");
            }
            if (uint64_count <= 0)
            {
                throw std::invalid_argument("uint64_count");
            }
#endif
            return ((value[uint64_count - 1] >> (bits_per_uint64 - 1)) & 1) != 0;
        }

        inline bool is_bit_set_uint(const uint64_t *value, int uint64_count, int bit_index)
        {
#ifdef _DEBUG
            if (value == nullptr)
            {
                throw std::invalid_argument("value");
            }
            if (uint64_count <= 0)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (bit_index < 0 || bit_index >= uint64_count * bits_per_uint64)
            {
                throw std::invalid_argument("bit_index");
            }
#endif
            int uint64_index = bit_index / bits_per_uint64;
            int sub_bit_index = bit_index % bits_per_uint64;
            return ((value[uint64_index] >> sub_bit_index) & 1) != 0;
        }

        inline void set_bit_uint(uint64_t *value, int uint64_count, int bit_index)
        {
#ifdef _DEBUG
            if (value == nullptr)
            {
                throw std::invalid_argument("value");
            }
            if (uint64_count <= 0)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (bit_index < 0 || bit_index >= uint64_count * bits_per_uint64)
            {
                throw std::invalid_argument("bit_index");
            }
#endif
            int uint64_index = bit_index / bits_per_uint64;
            int sub_bit_index = bit_index % bits_per_uint64;
            value[uint64_index] |= (static_cast<uint64_t>(1) << sub_bit_index);
        }

        int get_significant_bit_count_uint(const uint64_t *operand, int uint64_count);

        inline int get_significant_uint64_count_uint(const uint64_t *value, int uint64_count)
        {
#ifdef _DEBUG
            if (value == nullptr && uint64_count > 0)
            {
                throw std::invalid_argument("value");
            }
            if (uint64_count < 0)
            {
                throw std::invalid_argument("uint64_count");
            }
#endif
            value += uint64_count;
            for (int i = uint64_count; i > 0; --i)
            {
                if (*--value != 0)
                {
                    return i;
                }
            }
            return 0;
        }

        int get_power_of_two_uint(const uint64_t *operand, int uint64_count);

        int get_power_of_two_minus_one_uint(const uint64_t *operand, int uint64_count);

        void filter_highbits_uint(uint64_t *operand, int uint64_count, int bit_count);

        ConstPointer duplicate_uint_if_needed(const uint64_t *uint, int uint64_count, int new_uint64_count, bool force, MemoryPool &pool);

        int compare_uint_uint(const uint64_t *operand1, const uint64_t *operand2, int uint64_count);

        int compare_uint_uint(const uint64_t *operand1, int operand1_uint64_count, const uint64_t *operand2, int operand2_uint64_count);

        inline bool is_greater_than_uint_uint(const uint64_t *operand1, const uint64_t *operand2, int uint64_count)
        {
            return compare_uint_uint(operand1, operand2, uint64_count) > 0;
        }

        inline bool is_greater_than_or_equal_uint_uint(const uint64_t *operand1, const uint64_t *operand2, int uint64_count)
        {
            return compare_uint_uint(operand1, operand2, uint64_count) >= 0;
        }

        inline bool is_less_than_uint_uint(const uint64_t *operand1, const uint64_t *operand2, int uint64_count)
        {
            return compare_uint_uint(operand1, operand2, uint64_count) < 0;
        }

        inline bool is_less_than_or_equal_uint_uint(const uint64_t *operand1, const uint64_t *operand2, int uint64_count)
        {
            return compare_uint_uint(operand1, operand2, uint64_count) <= 0;
        }

        inline bool is_equal_uint_uint(const uint64_t *operand1, const uint64_t *operand2, int uint64_count)
        {
            return compare_uint_uint(operand1, operand2, uint64_count) == 0;
        }

        inline bool is_not_equal_uint_uint(const uint64_t *operand1, const uint64_t *operand2, int uint64_count)
        {
            return compare_uint_uint(operand1, operand2, uint64_count) != 0;
        }
    }
}

#endif // SEAL_UTIL_UINTCORE_H
