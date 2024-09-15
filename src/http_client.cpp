#include <string>
#include <span>
#include <cstddef>
#include <cstring>
#include <charconv>
#include <string_view>
#include <algorithm>
#include <iterator>
#include <format>

#include <curl/curl.h>

#include "http_client.hpp"

HTTPRequest& HTTPRequest::setPayload(std::string_view data)
{
    request_data = data;
    return *this;
}

HTTPRequest& HTTPRequest::addHeader(std::string_view key, std::string_view value)
{
    header.emplace(key, value);
    return *this;
}

HTTPRequest& HTTPRequest::setContentType(std::string_view type)
{
    return addHeader("Content-Type", type);
}

HTTPResponse::HTTPResponse(int status_code, std::string_view payload_str)
        : status(status_code)
{
    std::transform(std::begin(payload_str), std::end(payload_str),
                   std::back_inserter(payload),
                   [](char c) { return std::byte(c); });
}

void HTTPResponse::clear()
{
    status = 0;
    payload.clear();
    header.clear();
}

std::string_view HTTPResponse::payloadAsStr() const
{
    return {reinterpret_cast<const char*>(payload.data()), payload.size()};
}

HTTPSession::HTTPSession()
{
    handle = curl_easy_init();
    res.payload.reserve(CURL_MAX_WRITE_SIZE);
}

HTTPSession::~HTTPSession()
{
    if(handle != nullptr)
    {
        curl_easy_cleanup(handle);
    }
}

HTTPSession::HTTPSession(const HTTPSession& other)
{
    handle = curl_easy_duphandle(other.handle);

}

void HTTPSession::prepareForNewRequest()
{
    res.clear();
    curl_easy_reset(handle);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, HTTPSession::writeResponse);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &res);
    curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, HTTPSession::writeHeaders);
    curl_easy_setopt(handle, CURLOPT_HEADERDATA, &res);
}

curl_slist* headersFromReq(const HTTPRequest& req)
{
    curl_slist* headers = nullptr;
    for(const auto& [key, value]: req.header)
    {
        headers = curl_slist_append(
            headers, std::format("{}: {}", key, value).c_str());
    }
    return headers;
}

E<const HTTPResponse*> HTTPSession::get(const HTTPRequest& req)
{
    prepareForNewRequest();
    curl_easy_setopt(handle, CURLOPT_URL, req.url.c_str());
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headersFromReq(req));
    CURLcode code = curl_easy_perform(handle);
    if(code == CURLE_OK)
    {
        return &res;
    }
    return std::unexpected(runtimeError(curl_easy_strerror(code)));
}

E<const HTTPResponse*> HTTPSession::post(const HTTPRequest& req)
{
    prepareForNewRequest();
    curl_easy_setopt(handle, CURLOPT_URL, req.url.c_str());
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headersFromReq(req));
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, req.request_data.data());
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, req.request_data.size());

    CURLcode code = curl_easy_perform(handle);
    if(code == CURLE_OK)
    {
        return &res;
    }
    return std::unexpected(runtimeError(curl_easy_strerror(code)));
}

size_t HTTPSession::writeResponse(char *ptr, size_t size, size_t nmemb,
                                  void *res)
{
    size_t realsize = size * nmemb;
    HTTPResponse* b = reinterpret_cast<HTTPResponse*>(res);
    b->payload.resize(realsize);
    std::memcpy(b->payload.data(), ptr, realsize);
    return realsize;
}

size_t HTTPSession::writeHeaders(char *buffer, [[maybe_unused]] size_t size,
                                 size_t nitems, void *userdata)
{
    // “size” is always 1. See
    // https://curl.se/libcurl/c/CURLOPT_HEADERFUNCTION.html.

    if(nitems == 0)
    {
        return 0;
    }

    std::string line(buffer, nitems);
    // Remove trailing newline if present.
    if(line.back() == '\n')
    {
        // HTTP lines are delimited by “\r\n”.
        line.pop_back();
        line.pop_back();
    }

    if(line.empty())
    {
        // This means we are at the end of the header section. For now
        // we don’t do anything.
        return nitems;
    }

    HTTPResponse* res = reinterpret_cast<HTTPResponse*>(userdata);
    if(line.starts_with("HTTP/"))
    {
        // This is a status line.
        size_t first_space_index = line.find_first_of(' ');
        if(first_space_index == std::string::npos)
        {
            return 0;
        }
        size_t second_space_index =
            line.find_first_of(' ', first_space_index + 1);
        if(second_space_index == std::string::npos)
        {
            return 0;
        }
        std::from_chars(line.data() + first_space_index + 1,
                        line.data() + second_space_index,
                        res->status);
    }
    else
    {
        size_t colon_index = line.find_first_of(':');

        std::string_view key(std::begin(line),
                             std::next(std::begin(line), colon_index));
        size_t i = colon_index + 1;
        while(line[i] == ' ') i++;
        std::string_view value(std::next(std::begin(line), i), std::end(line));
        res->header.emplace(key, value);
    }

    return nitems;
}
