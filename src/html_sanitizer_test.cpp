#include <gtest/gtest.h>

#include "html_sanitizer.hpp"

TEST(HtmlSanitizer, SanitizeBasic)
{
    std::string html =
        "<div><p>Hello <a href=\"https://target.com\" "
        "onclick=\"alert()\">world</a><script>alert(1)</script></p></div>";
    auto snippet = HtmlSanitizer::extractAndSanitizeSnippet(
        html, "https://target.com", 500);
    ASSERT_TRUE(snippet.has_value());
    EXPECT_EQ(*snippet,
              "<p>Hello \n<a href=\"https://target.com\">world\n</a></p>");
}

TEST(HtmlSanitizer, FindTargetAndLimitLength)
{
    std::string html =
        "<article><h1>Title</h1><p>Lorem ipsum dolor sit amet. <a "
        "href=\"https://target.com/123\">Link</a> and some more text that "
        "should be truncated eventually if the limit is short.</p></article>";
    auto snippet = HtmlSanitizer::extractAndSanitizeSnippet(
        html, "https://target.com/123", 40);
    ASSERT_TRUE(snippet.has_value());
    EXPECT_TRUE(snippet->find("https://target.com/123") != std::string::npos);
    EXPECT_TRUE(snippet->find("<p>") != std::string::npos);
    EXPECT_TRUE(snippet->find("</p>") != std::string::npos);
}

TEST(HtmlSanitizer, NoTarget)
{
    std::string html = "<p>No link here</p>";
    auto snippet = HtmlSanitizer::extractAndSanitizeSnippet(
        html, "https://target.com", 500);
    ASSERT_FALSE(snippet.has_value());
}

TEST(HtmlSanitizer, DangerousAttributesRemoved)
{
    std::string html = "<p><a href=\"javascript:alert(1)\">Bad</a> <a "
                       "href=\"https://target.com\" style=\"color:red;\" "
                       "onmouseover=\"bad()\">Good</a></p>";
    auto snippet = HtmlSanitizer::extractAndSanitizeSnippet(
        html, "https://target.com", 500);
    ASSERT_TRUE(snippet.has_value());
    EXPECT_EQ(
        *snippet,
        "<p><a>Bad\n</a> \n<a href=\"https://target.com\">Good\n</a></p>");
}