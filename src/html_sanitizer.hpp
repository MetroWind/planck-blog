#pragma once
#include <optional>
#include <string>

class HtmlSanitizer
{
public:
    // Parses `raw_html`, removes unsafe tags/attributes, locates the <a>
    // tag linking to `target_url`, and returns a balanced HTML snippet
    // surrounding the link.
    static std::optional<std::string>
    extractAndSanitizeSnippet(const std::string& raw_html,
                              const std::string& target_url,
                              size_t max_length = 500);
};
