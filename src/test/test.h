/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// test.h: test header

#ifndef TEST_H
#define TEST_H

#pragma once

#ifdef _MSC_VER
#pragma warning(disable : 4996)
#endif

#include <gtest/gtest.h>

#include "athdns.h"

namespace test
{
    using rand_result = unsigned int;
    rand_result random_value();
    const CH *random_string(int = -1);

};  // namespace test


#endif
