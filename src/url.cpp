#include <expected>
#include <string>
#include <string_view>

#include <curl/curl.h>

#include "error.hpp"
#include "url.hpp"

E<URL> URL::fromStr(const char* u)
{
    URL url;
    url.init();
    if(curl_url_set(url.url, CURLUPART_URL, u, 0) != CURLUE_OK)
    {
        return std::unexpected(runtimeError(std::string("Invalid URL: ") + u));
    }
    return E<URL>{std::in_place, std::move(url)};
}

E<URL> URL::fromStr(const std::string& u)
{
    return fromStr(u.c_str());
}

URL::URL(const URL& rhs) : URL()
{
    *this = rhs;
}

URL::URL(URL&& rhs) : URL()
{
    std::swap(url, rhs.url);
}

URL& URL::operator=(const URL& rhs)
{
    if(url != nullptr)
    {
        curl_url_cleanup(url);
        url = nullptr;
    }
    if(rhs.url != nullptr)
    {
        url = curl_url_dup(rhs.url);
    }
    return *this;
}

URL& URL::operator=(URL&& rhs)
{
    if(url != nullptr)
    {
        curl_url_cleanup(url);
        url = nullptr;
    }
    std::swap(url, rhs.url);
    return *this;
}

URL::~URL()
{
    if(url != nullptr)
    {
        curl_url_cleanup(url);
        url = nullptr;
    }
}

void URL::init()
{
    if(url == nullptr)
    {
        url = curl_url();
    }
}

std::string URL::str() const
{
    if(url == nullptr) return "";
    char *u;
    if(curl_url_get(url, CURLUPART_URL, &u, 0) != CURLUE_OK)
    {
        return "";
    }
    std::string result = u;
    curl_free(u);
    return result;
}

std::string URL::host() const
{
    if(url == nullptr) return "";
    char* str = nullptr;
    if(curl_url_get(url, CURLUPART_HOST, &str, 0) != CURLUE_OK)
    {
        curl_free(str);
        return "";
    }
    std::string result = str;
    curl_free(str);
    return result;
}

URL& URL::host(const char* value)
{
    init();
    curl_url_set(url, CURLUPART_HOST, value, 0);
    return *this;
}

std::string URL::scheme() const
{
    if(url == nullptr) return "";
    char* str = nullptr;
    if(curl_url_get(url, CURLUPART_SCHEME, &str, 0) != CURLUE_OK)
    {
        curl_free(str);
        return "";
    }
    std::string result = str;
    curl_free(str);
    return result;
}

URL& URL::scheme(const char* value)
{
    init();
    curl_url_set(url, CURLUPART_SCHEME, value, 0);
    return *this;
}

std::string URL::port() const
{
    if(url == nullptr) return "";
    char* str = nullptr;
    if(curl_url_get(url, CURLUPART_PORT, &str, 0) != CURLUE_OK)
    {
        curl_free(str);
        return "";
    }
    std::string result = str;
    curl_free(str);
    return result;
}

URL& URL::port(const char* value)
{
    init();
    curl_url_set(url, CURLUPART_PORT, value, 0);
    return *this;
}

std::string URL::path() const
{
    if(url == nullptr) return "";
    char* str = nullptr;
    if(curl_url_get(url, CURLUPART_PATH, &str, 0) != CURLUE_OK)
    {
        curl_free(str);
        return "";
    }
    std::string result = str;
    curl_free(str);
    return result;
}

URL& URL::path(const char* value)
{
    init();
    curl_url_set(url, CURLUPART_PATH, value, 0);
    return *this;
}

std::string URL::query() const
{
    if(url == nullptr) return "";
    char* str = nullptr;
    if(curl_url_get(url, CURLUPART_QUERY, &str, 0) != CURLUE_OK)
    {
        curl_free(str);
        return "";
    }
    std::string result = str;
    curl_free(str);
    return result;
}

URL& URL::query(const char* value)
{
    init();
    curl_url_set(url, CURLUPART_QUERY, value, 0);
    return *this;
}

std::string URL::fragment() const
{
    if(url == nullptr) return "";
    char* str = nullptr;
    if(curl_url_get(url, CURLUPART_FRAGMENT, &str, 0) != CURLUE_OK)
    {
        curl_free(str);
        return "";
    }
    std::string result = str;
    curl_free(str);
    return result;
}

URL& URL::fragment(const char* value)
{
    init();
    curl_url_set(url, CURLUPART_FRAGMENT, value, 0);
    return *this;
}

std::string URL::user() const
{
    if(url == nullptr) return "";
    char* str = nullptr;
    if(curl_url_get(url, CURLUPART_USER, &str, 0) != CURLUE_OK)
    {
        curl_free(str);
        return "";
    }
    std::string result = str;
    curl_free(str);
    return result;
}

URL& URL::user(const char* value)
{
    init();
    curl_url_set(url, CURLUPART_USER, value, 0);
    return *this;
}

std::string URL::password() const
{
    if(url == nullptr) return "";
    char* str = nullptr;
    if(curl_url_get(url, CURLUPART_PASSWORD, &str, 0) != CURLUE_OK)
    {
        curl_free(str);
        return "";
    }
    std::string result = str;
    curl_free(str);
    return result;
}

URL& URL::password(const char* value)
{
    init();
    curl_url_set(url, CURLUPART_PASSWORD, value, 0);
    return *this;
}

std::string URL::zoneid() const
{
    if(url == nullptr) return "";
    char* str = nullptr;
    if(curl_url_get(url, CURLUPART_ZONEID, &str, 0) != CURLUE_OK)
    {
        curl_free(str);
        return "";
    }
    std::string result = str;
    curl_free(str);
    return result;
}

URL& URL::zoneid(const char* value)
{
    init();
    curl_url_set(url, CURLUPART_ZONEID, value, 0);
    return *this;
}

URL& URL::appendPath(std::string_view appendant)
{
    if(appendant.empty()) return *this;

    // Remove leading slashes.
    size_t begin = 0;
    while(begin < appendant.size() && appendant[begin] == '/')
    {
        begin++;
    }
    if(begin >= appendant.size()) return *this;
    std::string_view to_append = appendant.substr(begin, appendant.size());
    if(to_append.empty()) return *this;

    init();
    std::string existing_path = path();
    // Remove trailing slashes.
    while(!existing_path.empty() && existing_path.back() == '/')
    {
        existing_path.pop_back();
    }
    return path((existing_path + "/" + std::string(to_append)).c_str());
}
