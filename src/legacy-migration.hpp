#pragma once

#include <ctime>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <tuple>
#include <string_view>

#include "config.hpp"
#include "data.hpp"
#include "error.hpp"
#include "post.hpp"
#include "utils.hpp"

namespace fs = std::filesystem;

inline std::tuple<std::string_view, std::string_view>
parseHeaderLine(std::string_view line)
{
    auto idx = line.find(": ");
    return {line.substr(0, idx), line.substr(idx + 2)};
}

inline Post readLegacyPost(const fs::path& filename)
{
    std::ifstream file(filename);
    std::string line;
    bool header_done = false;
    Post p;
    p.author = "mw";
    p.markup = Post::COMMONMARK;
    while(std::getline(file, line))
    {
        if(line.empty() && !header_done)
        {
            header_done = true;
            continue;
        }

        if(!header_done)
        {
            auto [key, value] = parseHeaderLine(line);
            if(key == "Language")
            {
                std::string lang(value);
                toLower(lang);
                if(lang == "zh")
                {
                    p.language = "zh-CN";
                }
                else
                {
                    p.language = lang;
                }
            }
            else if(key == "Title")
            {
                p.title = value;
            }
            else if(key == "Time")
            {
                std::tm tm;
                std::stringstream ss{std::string(value)};
                ss >> std::get_time(&tm, "%Y-%m-%d %H:%M");
                p.publish_time = Clock::from_time_t(std::mktime(&tm));
            }
            else if(key == "Updated")
            {
                std::tm tm;
                std::stringstream ss{std::string(value)};
                ss >> std::get_time(&tm, "%Y-%m-%d %H:%M");
                p.update_time = Clock::from_time_t(std::mktime(&tm));
            }
            else if(key == "Renderer")
            {
                if(value == "asciidoctor")
                {
                    p.markup = Post::ASCIIDOC;
                }
            }
            else if(key == "Abstract")
            {
                p.abstract = value;
            }
        }
        else
        {
            p.raw_content += line;
            p.raw_content += "\n";
        }
    }
    return p;
}

inline std::vector<Post> discoverPosts(const fs::path& post_dir)
{
    std::vector<Post> ps;
    for(const fs::directory_entry& entry:
            fs::recursive_directory_iterator(post_dir))
    {
        if(!entry.is_regular_file())
        {
            continue;
        }
        ps.push_back(readLegacyPost(entry.path()));
    }
    return ps;
}

inline E<void> migrate(const fs::path& post_dir, const Configuration& config)
{
    ASSIGN_OR_RETURN(auto data_source, DataSourceSqlite::fromFile(
        (std::filesystem::path(config.data_dir) / "data.db").string()));
    for(const Post& p: discoverPosts(post_dir))
    {
        ASSIGN_OR_RETURN(int64_t id, data_source->saveDraft(Post(p)));
        DO_OR_RETURN(data_source->publishPost(id));
        DO_OR_RETURN(data_source->forceSetPostTimes(
            id, *p.publish_time, p.update_time));
    }
    return {};
}
