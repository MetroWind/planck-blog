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
#include "spdlog/spdlog.h"
#include "utils.hpp"
#include "url.hpp"

int main(int argc, char** argv)
{
    cxxopts::Options cmd_options("NS Weekly", "Naively simple weekly snippet");
    cmd_options.add_options()
        ("c,config", "Config file",
         cxxopts::value<std::string>()->default_value("/etc/nsweekly.yaml"))
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
        spdlog::error("Failed to load configuration: {}", errorMsg(conf.error()));
        return 3;
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

    return 0;
}
