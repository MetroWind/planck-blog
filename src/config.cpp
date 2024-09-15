#include <string>
#include <expected>
#include <filesystem>
#include <fstream>
#include <format>

#include <ryml.hpp>
#include <ryml_std.hpp>

#include "config.hpp"
#include "error.hpp"

namespace {

E<std::vector<char>> readFile(const std::filesystem::path& path)
{
    std::ifstream f(path, std::ios::binary);
    std::vector<char> content;
    content.reserve(102400);
    content.assign(std::istreambuf_iterator<char>(f),
                   std::istreambuf_iterator<char>());
    if(f.bad() || f.fail())
    {
        return std::unexpected(runtimeError(
            std::format("Failed to read file {}", path.string())));
    }

    return content;
}

template<class T>
bool getYamlValue(ryml::ConstNodeRef node, T& result)
{
    auto value = node.val();
    auto status = std::from_chars(value.begin(), value.end(), result);
    return status.ec == std::errc();
}

} // namespace

E<Configuration> Configuration::fromYaml(const std::filesystem::path& path)
{
    auto buffer = readFile(path);
    if(!buffer.has_value())
    {
        return std::unexpected(buffer.error());
    }

    ryml::Tree tree = ryml::parse_in_place(ryml::to_substr(*buffer));
    Configuration config;
    if(tree["data-dir"].has_key())
    {
        auto value = tree["data-dir"].val();
        config.data_dir = std::string(value.begin(), value.end());
    }
    if(tree["listen-address"].has_key())
    {
        auto value = tree["listen-address"].val();
        config.listen_address = std::string(value.begin(), value.end());
    }
    if(tree["listen-port"].has_key())
    {
        if(!getYamlValue(tree["listen-port"], config.listen_port))
        {
            return std::unexpected(runtimeError("Invalid port"));
        }
    }
    if(tree["client-id"].has_key())
    {
        auto value = tree["client-id"].val();
        config.client_id = std::string(value.begin(), value.end());
    }
    if(tree["client-secret"].has_key())
    {
        auto value = tree["client-secret"].val();
        config.client_secret = std::string(value.begin(), value.end());
    }
    if(tree["openid-url-prefix"].has_key())
    {
        auto value = tree["openid-url-prefix"].val();
        config.openid_url_prefix = std::string(value.begin(), value.end());
    }
    if(tree["url-prefix"].has_key())
    {
        auto value = tree["url-prefix"].val();
        config.url_prefix = std::string(value.begin(), value.end());
    }
    if(tree["default-lang"].has_key())
    {
        auto value = tree["default-lang"].val();
        config.default_lang = std::string(value.begin(), value.end());
    }
    return E<Configuration>{std::in_place, std::move(config)};
}
