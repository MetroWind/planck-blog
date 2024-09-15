#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <cstddef>
#include <span>
#include <unordered_map>

#include <curl/curl.h>
#include <spdlog/spdlog.h>

#include "error.hpp"

struct HTTPRequest
{
    std::string url;
    std::string request_data;
    std::unordered_map<std::string, std::string> header;

    HTTPRequest() = default;
    explicit HTTPRequest(std::string_view uri) : url(uri) {}
    HTTPRequest& setPayload(std::string_view data);
    HTTPRequest& addHeader(std::string_view key, std::string_view value);
    HTTPRequest& setContentType(std::string_view type);
    bool operator==(const HTTPRequest& rhs) const = default;
};

struct HTTPResponse
{
    int status;
    std::vector<std::byte> payload;
    std::unordered_map<std::string, std::string> header;

    HTTPResponse() = default;
    HTTPResponse(int status_code, std::string_view payload_str);
    void clear();
    std::string_view payloadAsStr() const;
};

class HTTPSessionInterface
{
public:
    virtual ~HTTPSessionInterface() = default;
    E<const HTTPResponse*> get(const std::string& uri)
    {
        return this->get(HTTPRequest(uri));
    }
    virtual E<const HTTPResponse*> get(const HTTPRequest& req) = 0;
    virtual E<const HTTPResponse*> post(const HTTPRequest& req) = 0;
};

// Threads should not share session
class HTTPSession : public virtual HTTPSessionInterface
{
public:
    HTTPSession();
    ~HTTPSession() override;
    HTTPSession(const HTTPSession&);
    HTTPSession& operator=(const HTTPSession&) = delete;

    using HTTPSessionInterface::get;
    // The returned pointer is garenteed to be non-null.
    E<const HTTPResponse*> get(const HTTPRequest& req) override;
    E<const HTTPResponse*> post(const HTTPRequest& req) override;

private:
    CURL* handle = nullptr;
    HTTPResponse res;

    void prepareForNewRequest();

    static size_t writeResponse(char *ptr, size_t size, size_t nmemb,
                                void *res_buffer);
    static size_t writeHeaders(char *buffer, size_t size, size_t nitems,
                               void *userdata);
};
