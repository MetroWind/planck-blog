#include <gtest/gtest.h>

#include "hash.hpp"

TEST(Hash, CanHashSHA256Half)
{
    EXPECT_EQ(Sha256HalfHasher().hashToHexStr("aaa"),
              "9834876dcfb05cb167a5c24953eba58c");
}
