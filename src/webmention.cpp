#include "webmention.hpp"

#include <algorithm>
#include <regex>
#include <sstream>
#include <thread>
#include <vector>

#include <mw/url.hpp>
#include <spdlog/spdlog.h>

#include "data.hpp"
#include "html_sanitizer.hpp"

void WebMentionManager::verifyWebMention(int64_t mention_id,
                                         const std::string& source,
                                         const std::string& target) const
{
    std::thread([this, mention_id, source, target]()
                { this->verifyWebMentionSync(mention_id, source, target); })
        .detach();
}

void WebMentionManager::verifyWebMentionSync(int64_t mention_id,
                                             const std::string& source,
                                             const std::string& target) const
{
    // SSRF mitigation
    auto source_url_opt = mw::URL::fromStr(source);
    if(!source_url_opt.has_value())
    {
        data_.deleteWebMention(mention_id);
        return;
    }
    std::string host = source_url_opt->host();
    if(!allow_internal_urls_)
    {
        if(host == "localhost" || host == "127.0.0.1" || host == "::1" ||
           host.starts_with("192.168.") || host.starts_with("10."))
        {
            data_.deleteWebMention(mention_id);
            return;
        }
    }

    auto session = session_factory_();
    mw::HTTPRequest req(source);
    req.follow_redirects = true;
    req.max_redirects = 20;
    req.timeout_ms = 10000;
    req.max_size = 1024 * 1024; // 1MB

    auto res = session->get(req);
    if(!res.has_value())
    {
        data_.deleteWebMention(mention_id);
        return;
    }

    const mw::HTTPResponse* response = res.value();
    if(response->status == 404 || response->status == 410)
    {
        data_.deleteWebMention(mention_id);
        return;
    }

    std::string payload(response->payloadAsStr());
    if(payload.find(target) == std::string::npos)
    {
        data_.deleteWebMention(mention_id);
        return;
    }

    std::string content_type;
    auto it = response->header.find("Content-Type");
    if(it != response->header.end())
    {
        content_type = it->second;
    }

    std::optional<std::string> snippet;
    if(content_type.find("text/html") != std::string::npos)
    {
        snippet =
            HtmlSanitizer::extractAndSanitizeSnippet(payload, target, 500);
    }
    else
    {
        size_t pos = payload.find(target);
        size_t start = (pos > 100) ? pos - 100 : 0;
        size_t len = 500;
        std::string raw_snippet = payload.substr(start, len);
        std::string esc;
        for(char c : raw_snippet)
        {
            switch(c)
            {
            case '&':
                esc += "&amp;";
                break;
            case '\"':
                esc += "&quot;";
                break;
            case '\'':
                esc += "&#39;";
                break;
            case '<':
                esc += "&lt;";
                break;
            case '>':
                esc += "&gt;";
                break;
            default:
                esc += c;
                break;
            }
        }
        snippet = esc;
    }

    data_.updateWebMention(mention_id, 1, std::nullopt, std::nullopt, snippet);
}

namespace
{

std::optional<std::string> discoverEndpoint(const mw::HTTPResponse& response)
{
    // 1. HTTP Link Header
    for(const auto& [key, value] : response.header)
    {
        std::string k = key;
        std::transform(k.begin(), k.end(), k.begin(), ::tolower);
        if(k == "link")
        {
            std::regex link_regex(
                R"regex(<([^>]+)>\s*;\s*rel=(?:"([^"]*)"|([^\s;,]+)))regex");
            auto words_begin =
                std::sregex_iterator(value.begin(), value.end(), link_regex);
            auto words_end = std::sregex_iterator();
            for(std::sregex_iterator i = words_begin; i != words_end; ++i)
            {
                std::smatch match = *i;
                std::string url = match[1].str();
                std::string rel =
                    match[2].length() > 0 ? match[2].str() : match[3].str();
                std::transform(rel.begin(), rel.end(), rel.begin(), ::tolower);
                std::istringstream iss(rel);
                std::string word;
                while(iss >> word)
                {
                    if(word == "webmention")
                    {
                        return url;
                    }
                }
            }
        }
    }

    // 2. HTML body
    std::string content_type;
    auto it = response.header.find("Content-Type");
    if(it != response.header.end())
    {
        content_type = it->second;
    }
    else
    {
        for(const auto& [key, val] : response.header)
        {
            std::string k = key;
            std::transform(k.begin(), k.end(), k.begin(), ::tolower);
            if(k == "content-type")
            {
                content_type = val;
            }
        }
    }

    if(content_type.find("text/html") != std::string::npos ||
       content_type.empty())
    {
        return HtmlSanitizer::discoverWebmentionEndpoint(
            std::string(response.payloadAsStr()));
    }

    return std::nullopt;
}

void notifyEndpoint(
    const WebMentionManager::HTTPSessionFactory& session_factory_,
    const std::string& endpoint, const std::string& source,
    const std::string& target)
{
    // Send POST
    auto post_session = session_factory_();
    mw::HTTPRequest post_req(endpoint);
    post_req.setContentType("application/x-www-form-urlencoded");

    std::string payload = "source=" + mw::URL::encode(source) +
                          "&target=" + mw::URL::encode(target);
    post_req.setPayload(payload);
    auto res = post_session->post(post_req);
    if(!res)
    {
        spdlog::error("Failed to send webmention to {}: {}", endpoint,
                      mw::errorMsg(res.error()));
    }
    else if((*res)->status >= 400)
    {
        spdlog::error("Webmention notification to {} returned status {}",
                      endpoint, (*res)->status);
    }
}

} // namespace

void WebMentionManager::sendWebMentions(
    const std::string& source_url,
    const std::set<std::string>& target_urls) const
{
    std::thread([this, source_url, target_urls]()
                { this->sendWebMentionsSync(source_url, target_urls); })
        .detach();
}

void WebMentionManager::sendWebMentionsSync(
    const std::string& source_url,
    const std::set<std::string>& target_urls) const
{
    for(const auto& target : target_urls)
    {
        auto session = session_factory_();
        mw::HTTPRequest req(target);
        req.follow_redirects = true;
        req.max_redirects = 20;
        req.timeout_ms = 10000;
        req.max_size = 1024 * 1024; // 1MB

        auto res = session->get(req);
        if(!res.has_value())
        {
            continue;
        }

        const mw::HTTPResponse* response = res.value();
        std::string final_url =
            response->final_url.empty() ? target : response->final_url;

        std::optional<std::string> endpoint = discoverEndpoint(*response);

        if(endpoint.has_value())
        {
            // Resolve URL
            auto target_url_obj = mw::URL::fromStr(final_url);
            if(target_url_obj.has_value())
            {
                target_url_obj->resolve(*endpoint);
                notifyEndpoint(session_factory_, target_url_obj->str(),
                               source_url, target);
            }
        }
    }
}
