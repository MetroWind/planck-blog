#pragma once

#include <set>
#include <string>
#include <unordered_map>

#include <mw/error.hpp>

#include "config.hpp"
#include "post.hpp"

// Render a post to bare HTML (HTML that only contains the post
// itself). This does not do template substitution to the content of
// the post.
mw::E<std::string> renderPost(const Post& p, const Configuration& conf);

// TODO: thread-safty
//
// Manage cache of posts
class PostCache
{
public:
    PostCache() = delete;
    PostCache(const Configuration& c) : conf(c) {}
    ~PostCache() = default;
    PostCache(const PostCache&) = delete;
    PostCache& operator=(const PostCache&) = delete;
    PostCache(PostCache&&) = default;
    PostCache& operator=(PostCache&&) = default;

    struct TimedRender
    {
        std::string html;
        mw::Time render_time;
    };

    mw::E<std::string> renderPost(const Post& p);

private:
    std::unordered_map<int64_t, TimedRender> cache;
    const Configuration& conf;
};

// Extracts absolute external links from a post's content.
// Note: This currently only parses and extracts links from Markdown
// (COMMONMARK) posts. For ASCIIDOC or other formats, it returns an empty set.
std::set<std::string> extractLinks(const Post& p);
