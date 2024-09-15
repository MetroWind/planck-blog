#pragma once

#include <string>
#include <expected>
#include <filesystem>

#include "error.hpp"

// What should be displayed on the index page if there is no session?
enum class GuestIndex
{
    USER_WEEKLY,                // Redirect to the weekly of a user.
};

struct Configuration
{
    std::string data_dir;
    std::string listen_address;
    int listen_port;
    std::string client_id;
    std::string client_secret;
    std::string openid_url_prefix;
    std::string url_prefix;
    std::string default_lang;

    static E<Configuration> fromYaml(const std::filesystem::path& path);

};
