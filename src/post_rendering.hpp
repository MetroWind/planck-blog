#pragma once

#include <string>
#include <unordered_map>

#include "config.hpp"
#include "post.hpp"
#include "error.hpp"

// Render a post to bare HTML (HTML that only contains the post
// itself). This also does template substitution to the content of the
// post.
E<std::string> renderPost(const Post& p, const Configuration& conf);

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
        Time render_time;
    };

    E<std::string> renderPost(const Post& p);

private:
    std::unordered_map<int64_t, TimedRender> cache;
    const Configuration& conf;
};
