#include "config.hpp"

#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <string>

#include <mw/error.hpp>
#include <ryml.hpp>
#include <ryml_std.hpp>

namespace
{

mw::E<std::vector<char>> readFile(const std::filesystem::path& path)
{
    std::ifstream f(path, std::ios::binary);
    std::vector<char> content;
    content.reserve(102400);
    content.assign(std::istreambuf_iterator<char>(f),
                   std::istreambuf_iterator<char>());
    if(f.bad() || f.fail())
    {
        return std::unexpected(mw::runtimeError(
            std::format("Failed to read file {}", path.string())));
    }

    return content;
}

template <class T> bool getYamlValue(ryml::ConstNodeRef node, T& result)
{
    auto value = node.val();
    auto status = std::from_chars(value.begin(), value.end(), result);
    return status.ec == std::errc();
}

} // namespace

mw::E<Configuration> Configuration::fromYaml(const std::filesystem::path& path)
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
        tree["data-dir"].load(&config.data_dir);
    }
    if(tree["attachment-dir"].readable())
    {
        tree["attachment-dir"].load(&config.attachment_dir);
    }
    if(tree["listen-address"].readable())
    {
        tree["listen-address"].load(&config.listen_address);
    }
    if(tree["listen-port"].readable())
    {
        if(!getYamlValue(tree["listen-port"], config.listen_port))
        {
            return std::unexpected(mw::runtimeError("Invalid port"));
        }
    }
    if(tree["client-id"].readable())
    {
        tree["client-id"].load(&config.client_id);
    }
    if(tree["client-secret"].readable())
    {
        tree["client-secret"].load(&config.client_secret);
    }
    if(tree["openid-url-prefix"].readable())
    {
        tree["openid-url-prefix"].load(&config.openid_url_prefix);
    }
    if(tree["base-url"].readable())
    {
        tree["base-url"].load(&config.base_url);
    }
    if(tree["languages"].is_seq())
    {
        for(const auto& lang : tree["languages"])
        {
            config.languages.emplace_back();
            lang.load(&config.languages.back());
        }
    }
    if(tree["blog-title"].readable())
    {
        tree["blog-title"].load(&config.blog_title);
    }
    if(tree["default-theme"].readable())
    {
        tree["default-theme"].load(&config.default_theme);
    }
    if(tree["substitutions"].readable())
    {
        if(tree["substitutions"]["nav-center"].readable())
        {
            tree["substitutions"]["nav-center"].load(
                &config.substitutions.nav_center);
        }
        if(tree["substitutions"]["after-post"].readable())
        {
            tree["substitutions"]["after-post"].load(
                &config.substitutions.after_post);
        }
    }

    return mw::E<Configuration>{std::in_place, std::move(config)};
}
