#pragma once
#include <optional>
#include <string>

class HtmlSanitizer
{
public:
    // Parses `raw_html`, removes unsafe tags/attributes, locates the <a>
    // tag linking to `target_url`, and returns a balanced HTML snippet.
    static std::optional<std::string>
    extractAndSanitizeSnippet(const std::string& raw_html,
                              const std::string& target_url,
                              size_t max_length = 500);

    // Parses HTML to find the first <link> or <a> with rel="webmention"
    // Returns the href attribute.
    static std::optional<std::string>
    discoverWebmentionEndpoint(const std::string& raw_html);
};
