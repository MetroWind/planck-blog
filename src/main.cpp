#include <memory>
#include <variant>
#include <filesystem>

#include <cxxopts.hpp>
#include <spdlog/spdlog.h>

#include "app.hpp"
#include "auth.hpp"
#include "config.hpp"
#include "data.hpp"
#include "http_client.hpp"
#include "legacy-migration.hpp"
#include "spdlog/common.h"
#include "spdlog/spdlog.h"
#include "utils.hpp"
#include "url.hpp"

int main(int argc, char** argv)
{
    // spdlog::set_level(spdlog::level::debug);
    cxxopts::Options cmd_options(
        "Planck Blog", "A naively simple blog server that is barely enough");
    cmd_options.add_options()
        ("c,config", "Config file",
         cxxopts::value<std::string>()->default_value("/etc/planck-blog.yaml"))
        ("legacy-migration", "Migrate the legacy posts from a directory and exit",
         cxxopts::value<std::string>())
        ("delete-post", "Delete a post or draft by ID and exit",
         cxxopts::value<int64_t>())
        ("set", "Set a runtime setting and exit. Example:"
         " --set pause-update-time=true. The only setting available right now"
         " is pause-update-time.",
         cxxopts::value<std::string>())
        ("h,help", "Print this message.");
    auto opts = cmd_options.parse(argc, argv);

    if(opts.count("help"))
    {
        std::cout << cmd_options.help() << std::endl;
        return 0;
    }

    const std::string config_file = opts["config"].as<std::string>();

    auto conf = Configuration::fromYaml(std::move(config_file));
    if(!conf.has_value())
    {
        spdlog::error("Failed to load configuration: {}",
                      errorMsg(conf.error()));
        return 3;
    }

    if(opts.count("legacy-migration") == 1)
    {
        auto ok_maybe = migrate(
            opts["legacy-migration"].as<std::string>(), *conf);
        if(ok_maybe)
        {
            return 0;
        }
        else
        {
            spdlog::error(errorMsg(ok_maybe.error()));
            return 1;
        }
    }

    if(opts.count("delete-post") == 1)
    {
        int64_t id = opts["delete-post"].as<int64_t>();
        auto data_source = DataSourceSqlite::fromFile(
            (std::filesystem::path(conf->data_dir) / "data.db").string());
        if(!data_source.has_value())
        {
            spdlog::error("Failed to create data source: {}",
                          errorMsg(data_source.error()));
            return 2;
        }
        E<void> ok_maybe = (*data_source)->deletePost(id);
        if(ok_maybe)
        {
            return 0;
        }
        else
        {
            spdlog::error(errorMsg(ok_maybe.error()));
            return 1;
        }
    }

    if(opts.count("set") == 1)
    {
        std::string _ = opts["set"].as<std::string>();
        std::string_view keyvalue(_);
        auto index = keyvalue.find('=');
        std::string_view key = strip(keyvalue.substr(0, index));
        if(key.empty())
        {
            spdlog::error("Invalid key");
            return 1;
        }
        nlohmann::json value = parseJSON(strip(keyvalue.substr(index+1)));
        if(value.is_discarded())
        {
            spdlog::error("Invalid value");
            return 1;
        }
        auto data_source = DataSourceSqlite::fromFile(
            (std::filesystem::path(conf->data_dir) / "data.db").string());
        if(!data_source.has_value())
        {
            spdlog::error("Failed to create data source: {}",
                          errorMsg(data_source.error()));
            return 2;
        }
        auto ok_maybe = (*data_source)->setValue(std::string(key),
                                                 std::move(value));
        if(ok_maybe)
        {
            return 0;
        }
        else
        {
            spdlog::error(errorMsg(ok_maybe.error()));
            return 1;
        }
    }

    auto url_prefix = URL::fromStr(conf->base_url);
    if(!url_prefix.has_value())
    {
        spdlog::error("Invalid base URL: {}", conf->base_url);
        return 4;
    }

    auto auth = AuthOpenIDConnect::create(
        *conf, url_prefix->appendPath("openid-redirect").str(),
        std::make_unique<HTTPSession>());
    if(!auth.has_value())
    {
        spdlog::error("Failed to create authentication module: {}",
                      std::visit([](const auto& e) { return e.msg; },
                                 auth.error()));
        return 1;
    }
    auto data_source = DataSourceSqlite::fromFile(
        (std::filesystem::path(conf->data_dir) / "data.db").string());
    if(!data_source.has_value())
    {
        spdlog::error("Failed to create data source: {}",
                      errorMsg(data_source.error()));
        return 2;
    }

    App app(*conf, *std::move(auth), *std::move(data_source));
    app.start();
    app.wait();

    return 0;
}
