#include <string>
#include <string_view>
#include <filesystem>

#include <magic.h>

#include "attachment.hpp"
#include "hash.hpp"

namespace {

// Probe and return the mime type of the given bytes. If the probe
// fails, return “application/octet-stream”.
std::string probeMimeType(std::string_view bytes)
{
    magic_t cookie = magic_open(MAGIC_MIME_TYPE);
    if(cookie == nullptr)
    {
        return "application/octet-stream";
    }
    if(magic_load(cookie, nullptr) != 0)
    {
        return "application/octet-stream";
    }
    const char* type_str = magic_buffer(cookie, bytes.data(), bytes.size());
    if(type_str == nullptr)
    {
        return "application/octet-stream";
    }
    std::string type = type_str;
    magic_close(cookie);
    return type;
}

} // namespace

Attachment AttachmentManager::attachmentFromBytes(
    const std::string& bytes, std::string_view filename) const
{
    Attachment att;
    att.hash = hasher.hashToHexStr(bytes);
    att.content_type = probeMimeType(bytes);
    att.original_name = filename;
    return att;
}

std::string AttachmentManager::path(const Attachment& att) const
{
    namespace fs = std::filesystem;
    return fs::path(att.hash.substr(0, 1)) /
        (att.hash + fs::path(att.original_name).extension().string());
}
