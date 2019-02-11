
#include "hash.h"
#include "dnsserver.h"

namespace hash
{
    namespace hash_fn
    {
        uint32_t hash_1(const CH *str)
        {
            const unsigned int seed = 131;
            unsigned int hash       = 0;
            while (*str) {
                const uint32_t c = static_cast<uint32_t>(*str++);
                hash             = hash * seed + c;
            }
            return (hash & 0x7FFFFFFF);
        }


        uint32_t hash_2(const CH *str)
        {
            unsigned int hash = 0;

            while (*str) {
                hash ^= ((hash << 7) ^ static_cast<uint32_t>(*str++) ^ (hash >> 3));
                if (*str == 0) {
                    break;
                }
                hash ^= (~((hash << 11) ^ static_cast<uint32_t>(*str++) ^ (hash >> 5)));
            }

            return (hash & 0x7FFFFFFF);
        }
    }  // namespace hash_fn


}  // namespace hash
