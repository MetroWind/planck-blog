#include <algorithm>
#include <expected>
#include <filesystem>
#include <fstream>

#include <ryml.hpp>
#include <ryml_std.hpp>

#include "theme.hpp"
#include "error.hpp"
#include "utils.hpp"

namespace fs = std::filesystem;

namespace
{
constexpr char THEME_INFO_FILE_NAME[] = "info.yaml";

E<Theme> readThemeDir(const fs::path& dir)
{
    // Read theme info from the info file.
    std::ifstream file(dir / THEME_INFO_FILE_NAME);
    std::vector<char> buffer(std::istreambuf_iterator<char>{file}, {});
    if(file.bad() || file.fail())
    {
        return std::unexpected(runtimeError("Failed to read theme info"));
    }
    file.close();

    ryml::Tree tree = ryml::parse_in_place(ryml::to_substr(buffer));
    Theme theme;
    theme.dir = dir;
    if(tree["parent"].has_key())
    {
        tree["parent"] >> theme.parent_name;
    }
    if(tree["name"].has_key())
    {
        tree["name"] >> theme.name;
    }
    else
    {
        theme.name = dir.filename();
    }

    // Find all stylesheets.
    for(const fs::directory_entry& entry: fs::directory_iterator(dir))
    {
        fs::path path = entry.path();
        std::string ext = path.extension();
        if(toLower(ext) != ".css")
        {
            continue;
        }
        theme.stylesheets.push_back(fs::relative(path, dir.parent_path()));
    }
    std::sort(theme.stylesheets.begin(), theme.stylesheets.end());
    return theme;
}

} // namespace

E<void> ThemeManager::loadDir(const std::filesystem::path& dir)
{
    for(const fs::directory_entry& entry: fs::directory_iterator(dir))
    {
        // First layer of dirs is themes. Each subdirectory is a theme.
        if(entry.is_directory())
        {
            fs::path path = entry.path();
            if(!fs::exists(path / THEME_INFO_FILE_NAME))
            {
                continue;
            }
            ASSIGN_OR_RETURN(Theme theme, readThemeDir(path));
            themes[theme.name] = std::move(theme);
        }
    }

    // Go though all themes to establish hierarchy.
    for(auto& theme_pair: themes)
    {
        Theme& theme = theme_pair.second;
        if(theme.parent_name.empty())
        {
            continue;
        }

        const auto it = themes.find(theme.parent_name);
        if(it == themes.end())
        {
            return std::unexpected(runtimeError(
                std::format("Couldn’t find theme {}’s parent, {}",
                            theme.name, theme.parent_name)));
        }
        theme.parent = &(it->second);
    }
    return {};
}

std::vector<std::filesystem::path> ThemeManager::stylesheets(
        const std::string& theme_name) const
{
    std::vector<std::filesystem::path> result;
    const Theme* theme = nullptr;
    const auto it = themes.find(theme_name);
    if(it == themes.end())
    {
        return result;
    }
    theme = &(it->second);
    while(theme)
    {
        result.insert(result.end(), theme->stylesheets.rbegin(),
                      theme->stylesheets.rend());
        theme = theme->parent;
    }
    std::reverse(result.begin(), result.end());
    return result;
}
