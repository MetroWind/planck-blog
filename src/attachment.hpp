#pragma once

#include <string>

#include <mw/crypto.hpp>
#include <mw/utils.hpp>

#include "config.hpp"

struct Attachment
{
    std::string original_name;
    std::string hash;
    mw::Time upload_time;
    std::string content_type;
};

class AttachmentManager
{
public:
    explicit AttachmentManager(mw::HasherInterface& h) : hasher(h) {}

    // Get an attachment object out of some bytes.
    Attachment attachmentFromBytes(const std::string& bytes,
                                   std::string_view filename,
                                   std::string_view content_type = "") const;
    // Get the path in the local file system of the attachment,
    // relative to the attachment dir set in the config.
    std::string path(const Attachment& att) const;

private:
    mw::HasherInterface& hasher;
};
