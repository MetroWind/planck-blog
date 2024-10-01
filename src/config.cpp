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
    if(tree["data-dir"].readable())
    {
        tree["data-dir"] >> config.data_dir;
    }
    if(tree["attachment-dir"].readable())
    {
        tree["attachment-dir"] >> config.attachment_dir;
    }
    if(tree["listen-address"].readable())
    {
        tree["listen-address"] >> config.listen_address;
    }
    if(tree["listen-port"].readable())
    {
        if(!getYamlValue(tree["listen-port"], config.listen_port))
        {
            return std::unexpected(runtimeError("Invalid port"));
        }
    }
    if(tree["client-id"].readable())
    {
        tree["client-id"] >> config.client_id;
    }
    if(tree["client-secret"].readable())
    {
        tree["client-secret"] >> config.client_secret;
    }
    if(tree["openid-url-prefix"].readable())
    {
        tree["openid-url-prefix"] >> config.openid_url_prefix;
    }
    if(tree["base-url"].readable())
    {
        tree["base-url"] >> config.base_url;
    }
    if(tree["languages"].is_seq())
    {
        for(const auto& lang: tree["languages"])
        {
            lang >> config.languages.emplace_back();
        }
    }
    if(tree["blog-title"].readable())
    {
        tree["blog-title"] >> config.blog_title;
    }
    if(tree["default-theme"].readable())
    {
        tree["default-theme"] >> config.default_theme;
    }
    if(tree["substitutions"].readable())
    {
        if(tree["substitutions"]["nav-center"].readable())
        {
            tree["substitutions"]["nav-center"] >>
                config.substitutions.nav_center;
        }
        if(tree["substitutions"]["after-post"].readable())
        {
            tree["substitutions"]["after-post"] >>
                config.substitutions.after_post;
        }
    }

    return E<Configuration>{std::in_place, std::move(config)};
}
