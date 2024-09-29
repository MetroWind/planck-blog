#include "post.hpp"


bool Post::isValidMarkupInt(int i)
{
    switch(i)
    {
    case COMMONMARK:
    case ASCIIDOC:
        return true;
    }
    return false;
}

std::string Post::markupToStr(Markup m)
{
    switch(m)
    {
    case COMMONMARK:
        return "CommonMark";
    case ASCIIDOC:
        return "AsciiDoc";
    }
    std::unreachable();
}

std::optional<Post::Markup> Post::markupFromStr(std::string_view m)
{
    if(m == "CommonMark")
    {
        return Post::COMMONMARK;
    }
    if(m == "AsciiDoc")
    {
        return Post::ASCIIDOC;
    }
    return std::nullopt;
}

std::ostream& operator<<(std::ostream& stream, const Post& p)
{
    stream << "Title: " << p.title << "\n"
           << "Abstract: " << p.abstract << "\n"
           << "Markup: " << Post::markupToStr(p.markup) << "\n"
           << "Language: " << p.language << "\n"
           << "Author: " << p.author;
    return stream;
}
