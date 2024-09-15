#include <gtest/gtest.h>

#include "post.hpp"
#include "error.hpp"
#include "test_utils.hpp"

TEST(Post, CanRenderAsciiDoc)
{
    Post p;
    p.markup = Post::ASCIIDOC;
    p.raw_content = "== Test\n\nIt’s a test\n";
    ASSIGN_OR_FAIL(std::string rendered, p.render());
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
