#include <chrono>

#include <gtest/gtest.h>

#include "utils.hpp"

TEST(Utils, CanStripStringFromLeft)
{
    EXPECT_EQ(lstrip(""), "");
    EXPECT_EQ(lstrip(" "), "");
    EXPECT_EQ(lstrip("  "), "");
    EXPECT_EQ(lstrip(" a "), "a ");
    EXPECT_EQ(lstrip("  a "), "a ");
    EXPECT_EQ(lstrip("a "), "a ");
}

TEST(Utils, CanStripStringFromRight)
{
    EXPECT_EQ(rstrip(""), "");
    EXPECT_EQ(rstrip(" "), "");
    EXPECT_EQ(rstrip("  "), "");
    EXPECT_EQ(rstrip(" a "), " a");
    EXPECT_EQ(rstrip(" a  "), " a");
    EXPECT_EQ(rstrip(" a"), " a");
}

TEST(Utils, CanStripStringFromBothSides)
{
    EXPECT_EQ(strip(""), "");
    EXPECT_EQ(strip(" "), "");
    EXPECT_EQ(strip("  "), "");
    EXPECT_EQ(strip(" a "), "a");
    EXPECT_EQ(strip(" a  "), "a");
    EXPECT_EQ(strip("a"), "a");
}
