#include "url.hpp"

#include <gtest/gtest.h>

TEST(URL, CanGetSetParts)
{
    auto url = URL::fromStr("http://example.com:1234/aaa/bbb");
    ASSERT_TRUE(url.has_value());
    EXPECT_EQ(url->path(), "/aaa/bbb");
    url->query("ccc=ddd");
    EXPECT_EQ(url->query(), "ccc=ddd");
    EXPECT_EQ(url->str(), "http://example.com:1234/aaa/bbb?ccc=ddd");
}

TEST(URL, CanAppendPath)
{
    {
        auto url = URL::fromStr("http://example.com/aaa/");
        ASSERT_TRUE(url.has_value());
        url->appendPath("/bbb/");
        EXPECT_EQ(url->str(), "http://example.com/aaa/bbb/");
        url->appendPath("///");
        EXPECT_EQ(url->str(), "http://example.com/aaa/bbb/");
    }
    {
        auto url = URL::fromStr("http://example.com");
        ASSERT_TRUE(url.has_value());
        url->appendPath("bbb");
        EXPECT_EQ(url->str(), "http://example.com/bbb");
    }
}
