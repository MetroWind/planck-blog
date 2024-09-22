#include <expected>
#include <string>
#include <format>

#include <cmark.h>

#include "exec.hpp"
#include "post_rendering.hpp"
#include "utils.hpp"
#include "error.hpp"
#include "config.hpp"

namespace
{

E<std::string> renderMarkdown(const std::string& src)
{
    char* html = cmark_markdown_to_html(src.data(), src.size(),
                                        CMARK_OPT_DEFAULT);
    if(html == nullptr)
    {
        return std::unexpected(runtimeError("Failed to render Markdown."));
    }
    std::string result = html;
    free(html);
    return result;
}

E<std::string> renderAsciiDoc(const std::string& src)
{
    std::string output;
    ASSIGN_OR_RETURN(Process proc, Process::exec(
        src, {"asciidoctor", "-a", "stylesheet!", "-s", "-o", "-", "-"},
        &output));
    ASSIGN_OR_RETURN(int status, proc.wait());
    if(status != 0)
    {
        return std::unexpected(runtimeError(std::format(
            "AsciiDoctor failed with code {}", status)));
    }
    return output;
}

} // namespace

E<std::string> renderPost(const Post& p, [[maybe_unused]] const Configuration& conf)
{
    switch(p.markup)
    {
    case Post::ASCIIDOC:
        return renderAsciiDoc(p.raw_content);
    case Post::COMMONMARK:
        return renderMarkdown(p.raw_content);
    }
    std::unreachable();
}

E<std::string> PostCache::renderPost(const Post& p)
{
    if(!p.id.has_value())
    {
        return ::renderPost(p, conf);
    }
    // Do not cache drafts.
    if(!p.publish_time.has_value())
    {
        return ::renderPost(p, conf);
    }

    auto it = cache.find(*p.id);
    if(it == cache.end())
    {
        ASSIGN_OR_RETURN(std::string rendered, ::renderPost(p, conf));
        cache[*p.id] = {rendered, Clock::now()};
        return rendered;
    }

    TimedRender& cached_render = it->second;
    Time post_time = *p.publish_time;
    if(p.update_time.has_value())
    {
        post_time = *p.update_time;
    }

    if(cached_render.render_time > post_time)
    {
        return cached_render.html;
    }
    else
    {
        ASSIGN_OR_RETURN(std::string rendered, ::renderPost(p, conf));
        cache[*p.id] = {rendered, Clock::now()};
        return rendered;
    }
}
