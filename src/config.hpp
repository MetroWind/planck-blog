#pragma once

#include <string>
#include <vector>
#include <expected>
#include <filesystem>
#include <unordered_map>

#include "error.hpp"

struct Configuration
{
    using StringMap = std::unordered_map<std::string, std::string>;

    std::string data_dir;
    std::string attachment_dir;
    std::string listen_address;
    int listen_port;
    std::string client_id;
    std::string client_secret;
    std::string openid_url_prefix;
    std::string base_url;
    std::vector<std::string> languages;
    std::string blog_title;
    std::string default_theme;

    StringMap vars;
    StringMap custom_vars;

    static E<Configuration> fromYaml(const std::filesystem::path& path);

};
