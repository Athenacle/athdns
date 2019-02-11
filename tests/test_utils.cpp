
#include "test.h"

#include <random>

namespace test
{
    using std::random_device;

    rand_result random_value()
    {
        static std::random_device rd;
        return rd();
    }


    const CH* random_string(int len)
    {
        size_t actual_size;
        if (len <= 0) {
            actual_size = 10 + random_value() % 10;
        } else {
            actual_size = static_cast<size_t>(len);
        }
        CH* buffer = new CH[actual_size + 1];
        for (size_t t = 0; t < actual_size; t++) {
            buffer[t] = random_value() % ('z' - 'a') + 'a';
        }
        buffer[actual_size] = '\0';
        return buffer;
    }

}  // namespace test
