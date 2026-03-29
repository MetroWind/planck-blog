#include "post_rendering.hpp"

#include <expected>
#include <format>
#include <string>

#include <macrodown/macrodown.h>
#include <macrodown/standard_library.h>
#include <mw/error.hpp>
#include <mw/exec.hpp>
#include <mw/utils.hpp>
#include <unistd.h>

#include "config.hpp"

namespace
{

mw::E<std::string> renderMarkdown(const std::string& src)
{
    macrodown::MacroDown md;
    macrodown::StandardLibrary::registerMacros(md.evaluator());

    auto ast = md.parse(src);
    if(!ast)
    {
        return std::unexpected(
            mw::runtimeError("Failed to parse Markdown with MacroDown."));
    }

    std::string html = md.render(*ast);
    return html;
}

mw::E<std::string> renderAsciiDoc(const std::string& src)
{
    std::string output;
    ASSIGN_OR_RETURN(mw::Process proc,
                     mw::Process::exec(src,
                                       {"asciidoctor", "-a", "stylesheet!",
                                        "-s", "-o", "-", "-"},
                                       &output));
    ASSIGN_OR_RETURN(int status, proc.wait());
    if(status != 0)
    {
        return std::unexpected(mw::runtimeError(
            std::format("AsciiDoctor failed with code {}", status)));
    }
    return output;
}

} // namespace

std::set<std::string> extractLinks(const Post& p)
{
    std::set<std::string> links;

    if(p.markup != Post::COMMONMARK)
    {
        return links;
    }

    macrodown::MacroDown md;
    auto ast = md.parse(p.raw_content);
    if(!ast)
    {
        return links;
    }

    ast->forEach(
        [&links, &md](const macrodown::Node& node)
        {
            if(std::holds_alternative<macrodown::Macro>(node.data))
            {
                const auto& m = std::get<macrodown::Macro>(node.data);
                if(m.name == "link" && !m.arguments.empty())
                {
                    std::string url = md.evaluator().evaluate(*m.arguments[0]);
                    if(url.starts_with("http://") ||
                       url.starts_with("https://"))
                    {
                        links.insert(url);
                    }
                }
            }
        });

    return links;
}

mw::E<std::string> renderPost(const Post& p,
                              [[maybe_unused]] const Configuration& conf)
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

mw::E<std::string> PostCache::renderPost(const Post& p)
{
    // If a post doesn’t have ID, it’s probably not in the DB yet.
    // Don’t bother to cache it.
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
        cache[*p.id] = {rendered, mw::Clock::now()};
        return rendered;
    }

    TimedRender& cached_render = it->second;
    mw::Time post_time = *p.publish_time;
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
        cache[*p.id] = {rendered, mw::Clock::now()};
        return rendered;
    }
}
