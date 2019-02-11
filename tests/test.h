
#ifndef TEST_H
#define TEST_H

#pragma once

#ifdef _MSC_VER
#pragma warning(disable : 4996)
#endif

#include <gtest/gtest.h>

#include "dnsserver.h"

namespace test
{
    using rand_result = unsigned int;
    rand_result random_value();
    const CH *random_string(int = -1);
};  // namespace test


#endif
