#pragma once

#include <functional>
#include <nlohmann/json.hpp>

template <typename Bytes>
nlohmann::json parseJSON(Bytes&& bs)
{
    return nlohmann::json::parse(bs, nullptr, false);
}