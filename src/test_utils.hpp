#pragma once

#include <gtest/gtest.h>

#include "error.hpp"
#include "utils.hpp"

#define _ASSIGN_OR_FAIL_INNER(tmp, var, val)  \
    auto tmp = val;                             \
    ASSERT_TRUE(isExpected(tmp));             \
    var = std::move(tmp).value()

// Val should be a rvalue.
#define ASSIGN_OR_FAIL(var, val)                                      \
    _ASSIGN_OR_FAIL_INNER(_CONCAT_NAMES(assign_or_return_tmp, __COUNTER__), var, val)

// Usage: ASSERT_TRUE(isExpected(functionThatReturnsExpected()));
template<typename T>
testing::AssertionResult isExpected(const E<T>& result)
{
    if (result.has_value())
        return testing::AssertionSuccess();
    else
        return testing::AssertionFailure() << errorMsg(result.error());
}
