#pragma once

#include <string>
#include <filesystem>
#include <unordered_map>
#include <vector>

#include "error.hpp"

struct Theme
{
    Theme* parent = nullptr;
    std::string parent_name;
    std::string name;
    // Full path of the theme dir.
    std::filesystem::path dir;
    // Paths of stylesheet files, relative to the themes dir (which
    // contains all the themes), sorted by filename.
    std::vector<std::filesystem::path> stylesheets;
};

class ThemeManager
{
public:
    E<void> loadDir(const std::filesystem::path& dir);

    // Return all the stylesheets required for the specified theme,
    // including the stylesheets from the parents up to a root theme.
    // The stylesheets are arranged in an order that is suitable to be
    // referenced in an HTML file. If the theme is not found, return
    // an empty vector. The returned paths are relative to the themes
    // dir.
    std::vector<std::filesystem::path> stylesheets(
        const std::string& theme_name) const;

    // Return the names of all themes.
    std::vector<std::string> themeNames() const;

private:
    std::unordered_map<std::string, Theme> themes;
};
