#pragma once

#include <algorithm>
#include <cctype>
#include <chrono>
#include <string>
#include <string_view>
#include <filesystem>
#include <stdio.h>
#include <system_error>

#include <nlohmann/json.hpp>
#include <curl/curl.h>

#include "error.hpp"

#define _CONCAT_NAMES_INNER(a, b) a##b
#define _CONCAT_NAMES(a, b) _CONCAT_NAMES_INNER(a, b)
#define _ASSIGN_OR_RETURN_INNER(tmp, var, val)  \
    auto tmp = val;                             \
    if(!tmp.has_value()) {                      \
        return std::unexpected(tmp.error());    \
    }                                           \
    var = std::move(tmp).value()

// Val should be a rvalue.
#define ASSIGN_OR_RETURN(var, val)                                      \
    _ASSIGN_OR_RETURN_INNER(_CONCAT_NAMES(assign_or_return_tmp, __COUNTER__), var, val)

// Val should be a rvalue.
#define DO_OR_RETURN(val)                               \
    if(auto rt = val; !rt.has_value())                  \
    {                                                   \
        return std::unexpected(std::move(rt).error());  \
    }

using Clock = std::chrono::system_clock;
using Time = std::chrono::time_point<Clock>;

template <typename Bytes>
nlohmann::json parseJSON(Bytes&& bs)
{
    return nlohmann::json::parse(bs, nullptr, false);
}

inline std::string urlEncode(std::string_view s)
{
    char* url_raw = curl_easy_escape(nullptr, s.data(), s.size());
    std::string url(url_raw);
    curl_free(url_raw);
    return url;
}

inline int64_t timeToSeconds(const Time& t)
{
    return std::chrono::duration_cast<std::chrono::seconds>(
        t.time_since_epoch()).count();
}

inline Time secondsToTime(const int64_t t)
{
    return Time(std::chrono::seconds(t));
}

inline E<Time> strToDate(const std::string& s)
{
    std::tm t;
    std::istringstream ss(s);
    ss >> std::get_time(&t, "%Y-%m-%d");
    if(ss.fail())
    {
        return std::unexpected(runtimeError("Invalid date"));
    }
    std::chrono::year_month_day date(
        std::chrono::year(t.tm_year + 1900),
        std::chrono::month(t.tm_mon + 1),
        std::chrono::day(t.tm_mday));
    if(!date.ok())
    {
        return std::unexpected(runtimeError("Invalid date"));
    }
    return std::chrono::sys_days(date);
}

template<typename NumType>
E<NumType> strToNumber(std::string_view s)
{
    NumType x{};
    auto begin = std::begin(s);
    auto end = std::end(s);
    auto rt = std::from_chars(begin, end, x);
    if(rt.ptr == end)
    {
        return x;
    }
    if(rt.ec == std::errc::result_out_of_range)
    {
        return std::unexpected(runtimeError("out of range"));
    }
    if(rt.ptr > begin)
    {
        return std::unexpected(runtimeError(
            "Only part of the string can be converted to number"));
    }
    if(rt.ptr == begin)
    {
        return std::unexpected(runtimeError(
            "Failed to convert string to number"));
    }
    std::unreachable();
}

// Lower case a string in-place.
inline std::string& toLower(std::string& s)
{
    std::transform(s.begin(), s.end(), s.begin(),
    [](unsigned char c){ return std::tolower(c); });
    return s;
}
