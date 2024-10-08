#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "error.hpp"
#include "utils.hpp"

class Post
{
public:
    enum Markup
    {
        COMMONMARK,
        ASCIIDOC,
    };

    std::optional<int64_t> id;
    Markup markup;
    std::string title;
    std::string abstract;
    std::string raw_content;
    // Drafts do not have publish time.
    std::optional<Time> publish_time;
    std::optional<Time> update_time;
    // The IETF BCP 47 language tag (RFC 5646) of the post.
    std::string language;
    std::string author;

    bool operator==(const Post& rhs) const = default;

    static bool isValidMarkupInt(int i);
    static std::string markupToStr(Markup m);
    static std::optional<Markup> markupFromStr(std::string_view m);

    friend std::ostream& operator<<(std::ostream& stream, const Post& p);
};
