#include <expected>
#include <format>

#include <cmark.h>
#include <spdlog/spdlog.h>

#include "error.hpp"
#include "exec.hpp"
#include "post.hpp"
#include "utils.hpp"

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

bool Post::isValidMarkupInt(int i)
{
    switch(i)
    {
    case MARKDOWN:
    case ASCIIDOC:
        return true;
    }
    return false;
}

E<std::string> Post::render() const
{
    switch(markup)
    {
    case MARKDOWN:
        return renderMarkdown(raw_content);
    case ASCIIDOC:
        return renderAsciiDoc(raw_content);
    default:
        return std::unexpected(runtimeError(
            "Somebody forgot to add a switch case for a weekly format!"));
    }
}
