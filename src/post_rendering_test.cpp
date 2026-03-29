#include <gtest/gtest.h>
#include <mw/error.hpp>
#include <mw/test_utils.hpp>

#include "config.hpp"
#include "post.hpp"
#include "post_rendering.hpp"

TEST(Post, CanRenderAsciiDoc)
{
    Configuration conf;
    Post p;
    p.markup = Post::ASCIIDOC;
    p.raw_content = "== Test\n\nIt’s a test\n";
    ASSIGN_OR_FAIL(std::string rendered, renderPost(p, conf));
    EXPECT_EQ(rendered, R"(<div class="sect1">
<h2 id="_test">Test</h2>
<div class="sectionbody">
<div class="paragraph">
<p>It’s a test</p>
</div>
</div>
</div>
)");
}

TEST(Post, CanExtractLinks)
{
    Post p;
    p.markup = Post::COMMONMARK;
    p.raw_content = "Here is a [link](https://example.com) and another "
                    "[one](http://test.com) and [invalid](/local).";
    std::set<std::string> links = extractLinks(p);
    ASSERT_EQ(links.size(), 2);
    EXPECT_EQ(links.count("http://test.com"), 1);
    EXPECT_EQ(links.count("https://example.com"), 1);

    Post p2;
    p2.markup = Post::ASCIIDOC;
    p2.raw_content = "Here is a [link](https://example.com)";
    std::set<std::string> links2 = extractLinks(p2);
    EXPECT_TRUE(links2.empty());
}

TEST(Post, CanRenderMarkdown)
{
    Configuration conf;
    Post p;
    p.markup = Post::COMMONMARK;
    p.raw_content = "# Test\n\nIt’s a test\n";
    ASSIGN_OR_FAIL(std::string rendered, renderPost(p, conf));
    EXPECT_EQ(rendered, "<h1>Test</h1>\n<p>It’s a test</p>\n");
}
