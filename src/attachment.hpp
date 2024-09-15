#pragma once

#include <string>

#include "utils.hpp"

struct Attachment
{
    std::string original_name;
    std::string hash;
    Time upload_time;
    std::string content_type;
};
