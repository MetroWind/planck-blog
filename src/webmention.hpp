#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <string>

#include <mw/http_client.hpp>

#include "data.hpp"

class WebMentionManager
{
public:
    using HTTPSessionFactory =
        std::function<std::unique_ptr<mw::HTTPSessionInterface>()>;

    WebMentionManager(
        DataSourceInterface& data,
        HTTPSessionFactory factory = []()
        { return std::make_unique<mw::HTTPSession>(); },
        bool allow_internal_urls = false)
        : data_(data), session_factory_(std::move(factory)),
          allow_internal_urls_(allow_internal_urls)
    {
    }
    ~WebMentionManager() = default;

    // Asynchronous public interfaces
    void sendWebMentions(const std::string& source_url,
                         const std::set<std::string>& target_urls) const;

    void verifyWebMention(int64_t mention_id, const std::string& source,
                          const std::string& target) const;

    // Synchronous execution logic (exposed for unit testing)
    void sendWebMentionsSync(const std::string& source_url,
                             const std::set<std::string>& target_urls) const;

    void verifyWebMentionSync(int64_t mention_id, const std::string& source,
                              const std::string& target) const;

private:
    DataSourceInterface& data_;
    HTTPSessionFactory session_factory_;
    const bool allow_internal_urls_;
};
