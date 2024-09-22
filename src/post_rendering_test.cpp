#include <gtest/gtest.h>

#include "config.hpp"
#include "post.hpp"
#include "post_rendering.hpp"
#include "error.hpp"
#include "test_utils.hpp"

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
