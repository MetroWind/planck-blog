#include "json_utils.hpp"
#include <exception>
#include <iterator>
#include <pthread.h>
#include <string_view>
#include <memory>
#include <vector>
#include <expected>
#include <tuple>
#include <optional>
#include <chrono>

#include <spdlog/spdlog.h>
#include <sqlite3.h>
#include <nlohmann/json.hpp>

#include "attachment.hpp"
#include "data.hpp"
#include <mw/database.hpp>
#include <mw/error.hpp>
#include <mw/utils.hpp>
#include "post.hpp"

namespace {
mw::E<Post> postFromRow(const std::tuple<int, int, std::string, std::string,
                    std::string, int64_t, int64_t, std::string, std::string>&
                    row)
{
    int markup = std::get<1>(row);
    if(!Post::isValidMarkupInt(markup))
    {
        return std::unexpected(mw::runtimeError(std::format(
            "Invalid markup: {}", markup)));
    }
    Post p;
    p.id = std::get<0>(row);
    p.markup = static_cast<Post::Markup>(markup);
    p.title = std::move(std::get<2>(row));
    p.abstract = std::move(std::get<3>(row));
    p.raw_content = std::move(std::get<4>(row));
    int64_t ptime = std::get<5>(row);
    if(ptime != 0)
    {
        p.publish_time = mw::secondsToTime(ptime);
    }
    int64_t utime = std::get<6>(row);
    if(utime != 0)
    {
        p.update_time = mw::secondsToTime(utime);
    }
    p.language = std::move(std::get<7>(row));
    p.author = std::move(std::get<8>(row));
    return p;
}

} // namespace

mw::E<nlohmann::json> DataSourceInterface::getValueWithDefault(
        const std::string& key, nlohmann::json&& default_value) const
{
    ASSIGN_OR_RETURN(std::optional<nlohmann::json> v, this->getValue(key));
    if(v.has_value())
    {
        return *v;
    }
    else
    {
        return default_value;
    }
}

mw::E<std::unique_ptr<DataSourceSqlite>>
DataSourceSqlite::fromFile(const std::string& db_file)
{
    auto data_source = std::make_unique<DataSourceSqlite>();
    ASSIGN_OR_RETURN(data_source->db, mw::SQLite::connectFile(db_file));
    DO_OR_RETURN(data_source->setSchemaVersion(DB_SCHEMA_VERSION));
    DO_OR_RETURN(data_source->db->execute(
        "CREATE TABLE IF NOT EXISTS Posts "
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, markup INTEGER, title TEXT,"
        " abstract TEXT, content TEXT, publish_time INTEGER DEFAULT 0,"
        " update_time INTEGER DEFAULT 0, language TEXT, author TEXT);"));
    DO_OR_RETURN(data_source->db->execute(
        "CREATE TABLE IF NOT EXISTS Attachments "
        "(hash TEXT NOT NULL, original_name TEXT, upload_time INTEGER,"
        " content_type TEXT NOT NULL, PRIMARY KEY (hash));"));
    DO_OR_RETURN(data_source->db->execute(
        "CREATE TABLE IF NOT EXISTS AttachmentReferrals "
        "(hash TEXT, origin TEXT, request_count INTEGER,"
        " FOREIGN KEY (hash) REFERENCES Attachments(hash) ON DELETE CASCADE"
        " ON UPDATE CASCADE);"));
    DO_OR_RETURN(data_source->db->execute(
        "CREATE TABLE IF NOT EXISTS KeyValues "
        "(key TEXT PRIMARY KEY, value TEXT);"));
    return data_source;
}

mw::E<std::unique_ptr<DataSourceSqlite>> DataSourceSqlite::newFromMemory()
{
    return fromFile(":memory:");
}

mw::E<int64_t> DataSourceSqlite::getSchemaVersion() const
{
    return db->evalToValue<int64_t>("PRAGMA user_version;");
}

mw::E<std::vector<Post>> DataSourceSqlite::getPosts() const
{
    return filterPosts("WHERE publish_time != 0 ORDER BY publish_time DESC");
}

mw::E<std::vector<Post>> DataSourceSqlite::getPosts(int start, int count) const
{
    return filterPosts(std::format(
        "WHERE publish_time != 0 ORDER BY publish_time DESC LIMIT {} OFFSET {}",
        count, start));
}

mw::E<std::optional<Post>> DataSourceSqlite::getPost(int64_t id) const
{
    ASSIGN_OR_RETURN(std::vector<Post> ps, filterPosts(
        std::format("WHERE publish_time != 0 AND id = {}", id)));
    if(ps.empty())
    {
        return std::nullopt;
    }
    if(ps.size() > 1)
    {
        return std::unexpected(mw::runtimeError(
            "Something weird happened; duplicated post ID???"));
    }
    return ps[0];
}

mw::E<std::vector<Post>> DataSourceSqlite::getPostExcerpts() const
{
    ASSIGN_OR_RETURN(
        auto rows, (db->eval<int64_t, std::string, std::string, std::string>(
            "SELECT id, title, abstract, language FROM Posts WHERE "
            "publish_time != 0 ORDER BY publish_time DESC;")));
    // Converting rows to post objects.
    std::vector<Post> posts;
    posts.reserve(rows.size());
    for(auto& row: rows)
    {
        Post p;
        p.id = std::get<0>(row);
        p.title = std::move(std::get<1>(row));
        p.abstract = std::move(std::get<2>(row));
        p.language = std::move(std::get<3>(row));
        posts.push_back(std::move(p));
    }
    return posts;
}

mw::E<void> DataSourceSqlite::updatePost(Post&& new_post) const
{
    if(!new_post.id.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Trying to update a post without ID"));
    }
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "UPDATE Posts SET markup = ?, title = ?, abstract = ?, content = ?, "
        "update_time = ?, language = ? WHERE id = ?;"));
    DO_OR_RETURN(sql.bind(
        static_cast<int>(new_post.markup), new_post.title, new_post.abstract,
        new_post.raw_content, mw::timeToSeconds(mw::Clock::now()), new_post.language,
        *new_post.id));
    DO_OR_RETURN(db->execute(std::move(sql)));
    int64_t rows_count = db->changedRowsCount();
    if(rows_count == 0)
    {
        return std::unexpected(mw::runtimeError("Post not found"));
    }
    if(rows_count != 1)
    {
        return std::unexpected(mw::runtimeError(
            "Something weird happened when updating the post. Behavior is "
            "undefined"));
    }
    return {};
}

mw::E<void> DataSourceSqlite::updatePostNoUpdateTime(const Post& new_post) const
{
    if(!new_post.id.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Trying to update a post without ID"));
    }
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "UPDATE Posts SET markup = ?, title = ?, abstract = ?, content = ?, "
        "language = ? WHERE id = ?;"));
    DO_OR_RETURN(sql.bind(
        static_cast<int>(new_post.markup), new_post.title, new_post.abstract,
        new_post.raw_content, new_post.language, *new_post.id));
    DO_OR_RETURN(db->execute(std::move(sql)));
    int64_t rows_count = db->changedRowsCount();
    if(rows_count == 0)
    {
        return std::unexpected(mw::runtimeError("Post not found"));
    }
    if(rows_count != 1)
    {
        return std::unexpected(mw::runtimeError(
            "Something weird happened when updating the post. Behavior is "
            "undefined"));
    }
    return {};
}

mw::E<int64_t> DataSourceSqlite::saveDraft(Post&& new_draft) const
{
    if(new_draft.id.has_value())
    {
        return std::unexpected(mw::runtimeError("New draft should not have ID"));
    }
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "INSERT INTO Posts (markup, title, abstract, content, language, author)"
        " VALUES (?, ?, ?, ?, ?, ?)"));
    DO_OR_RETURN(sql.bind(
        static_cast<int>(new_draft.markup), new_draft.title, new_draft.abstract,
        new_draft.raw_content, new_draft.language, new_draft.author));
    DO_OR_RETURN(db->execute(std::move(sql)));
    return db->lastInsertRowID();
}

mw::E<std::vector<Post>> DataSourceSqlite::getDrafts() const
{
    return filterPosts("WHERE publish_time = 0");
}

mw::E<std::optional<Post>> DataSourceSqlite::getDraft(int64_t id) const
{
    ASSIGN_OR_RETURN(std::vector<Post> ps, filterPosts(std::format(
        "WHERE publish_time = 0 AND id = {}", id)));
    if(ps.empty())
    {
        return std::nullopt;
    }
    if(ps.size() > 1)
    {
        return std::unexpected(mw::runtimeError(
            "Something weird happened; duplicated draft ID???"));
    }
    return ps[0];
}

mw::E<void> DataSourceSqlite::editDraft(const Post& draft) const
{
    if(!draft.id.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Trying to edit a draft without ID"));
    }
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "UPDATE Posts SET markup = ?, title = ?, abstract = ?, content = ?, "
        "language = ? WHERE id = ? AND publish_time = 0;"));
    DO_OR_RETURN(sql.bind(
        static_cast<int>(draft.markup), draft.title, draft.abstract,
        draft.raw_content, draft.language, *draft.id));
    DO_OR_RETURN(db->execute(std::move(sql)));

    int64_t rows_count = db->changedRowsCount();
    if(rows_count == 0)
    {
        return std::unexpected(mw::runtimeError("Draft not found"));
    }
    if(rows_count != 1)
    {
        return std::unexpected(mw::runtimeError(
            "Something weird happened when editing the draft. Behavior is "
            "undefined"));
    }
    return {};
}

mw::E<void> DataSourceSqlite::publishPost(int64_t id) const
{
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "UPDATE Posts SET publish_time = ? WHERE id = ? AND publish_time = 0;"));
    DO_OR_RETURN(sql.bind(mw::timeToSeconds(mw::Clock::now()), id));
    DO_OR_RETURN(db->execute(std::move(sql)));
    int64_t rows_count = db->changedRowsCount();
    if(rows_count == 0)
    {
        return std::unexpected(mw::runtimeError("Draft not found"));
    }
    if(rows_count != 1)
    {
        return std::unexpected(mw::runtimeError(
            "Something weird happened when publishing. Behavior is undefined"));
    }
    return {};
}

mw::E<void> DataSourceSqlite::deletePost(int64_t id) const
{
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "DELETE FROM Posts  WHERE id = ?;"));
    DO_OR_RETURN(sql.bind(id));
    DO_OR_RETURN(db->execute(std::move(sql)));
    if(db->changedRowsCount() != 1)
    {
        return std::unexpected(mw::runtimeError("Failed to delete post."));
    }
    return {};
}

mw::E<void> DataSourceSqlite::addAttachment(Attachment&& att) const
{
    ASSIGN_OR_RETURN(mw::SQLiteStatement sql, db->statementFromStr(
        "INSERT OR IGNORE INTO Attachments (original_name, hash, upload_time,"
        " content_type) VALUES (?, ?, ?, ?);"));
    DO_OR_RETURN(sql.bind(att.original_name, att.hash,
                          mw::timeToSeconds(mw::Clock::now()), att.content_type));
    return db->execute(std::move(sql));
}

mw::E<std::optional<Attachment>>
DataSourceSqlite::getAttachment(const std::string& hash) const
{
    ASSIGN_OR_RETURN(mw::SQLiteStatement sql, db->statementFromStr(
        "SELECT original_name, upload_time, content_type FROM Attachments "
        "WHERE hash = ?;"));
    DO_OR_RETURN(sql.bind(hash));
    ASSIGN_OR_RETURN(auto rows, (db->eval<std::string, int64_t, std::string>(
        std::move(sql))));
    if(rows.empty())
    {
        return std::nullopt;
    }
    Attachment att;
    att.original_name = std::get<0>(rows[0]);
    att.hash = hash;
    att.upload_time = mw::secondsToTime(std::get<1>(rows[0]));
    att.content_type = std::get<2>(rows[0]);
    return att;
}

mw::E<std::vector<Attachment>> DataSourceSqlite::getAttachments() const
{
    ASSIGN_OR_RETURN(
        auto rows, (db->eval<std::string, std::string, int64_t, std::string>(
            "SELECT original_name, hash, upload_time, content_type FROM "
            "Attachments ORDER BY upload_time DESC;")));
    std::vector<Attachment> result;
    for(const auto& row: rows)
    {
        result.emplace_back(
            std::get<0>(row),
            std::get<1>(row),
            mw::secondsToTime(std::get<2>(row)),
            std::get<3>(row)
        );
    }
    return result;
}

mw::E<void> DataSourceSqlite::deleteAttachment(const std::string& hash) const
{
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "DELETE FROM Attachments WHERE hash = ?;"));
    DO_OR_RETURN(sql.bind(hash));
    DO_OR_RETURN(db->execute(std::move(sql)));
    if(db->changedRowsCount() != 1)
    {
        return std::unexpected(mw::runtimeError("Failed to delete attachment."));
    }
    return {};
}

mw::E<DataSourceInterface::ReferralCounts>
DataSourceSqlite::getReferralsOfAttachment(const std::string& hash) const
{
    ASSIGN_OR_RETURN(mw::SQLiteStatement sql, db->statementFromStr(
        "SELECT origin, request_count FROM AttachmentReferrals "
        "WHERE hash = ?;"));
    DO_OR_RETURN(sql.bind(hash));
    ASSIGN_OR_RETURN(auto rows, (db->eval<std::string, int64_t>(std::move(sql))));
    DataSourceInterface::ReferralCounts refs;
    for(auto& row: rows)
    {
        refs[std::get<0>(row)] = std::get<1>(row);
    }
    return refs;
}

mw::E<void> DataSourceSqlite::addAttachmentReferral(
    const std::string& attachment_hash, const std::string& url) const
{
    ASSIGN_OR_RETURN(mw::SQLiteStatement sql, db->statementFromStr(
        "SELECT request_count FROM AttachmentReferrals "
        "WHERE hash = ? AND origin = ?;"));
    DO_OR_RETURN(sql.bind(attachment_hash, url));
    ASSIGN_OR_RETURN(auto rows, db->eval<int64_t>(std::move(sql)));
    if(rows.empty())
    {
        ASSIGN_OR_RETURN(mw::SQLiteStatement sql, db->statementFromStr(
            "INSERT INTO AttachmentReferrals (hash, origin, request_count) "
            "VALUES (?, ?, 1);"));
        DO_OR_RETURN(sql.bind(attachment_hash, url));
        return db->execute(std::move(sql));
    }
    else
    {
        ASSIGN_OR_RETURN(mw::SQLiteStatement sql, db->statementFromStr(
            "UPDATE AttachmentReferrals SET request_count = request_count + 1 "
            "WHERE hash = ? AND origin = ?;"));
        DO_OR_RETURN(sql.bind(attachment_hash, url));
        return db->execute(std::move(sql));
    }
}

mw::E<void> DataSourceSqlite::forceSetPostTimes(
    int64_t id, const mw::Time& publish, const std::optional<mw::Time>& update) const
{
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "UPDATE Posts SET publish_time = ? WHERE id = ?;"));
    DO_OR_RETURN(sql.bind(mw::timeToSeconds(publish), id));
    DO_OR_RETURN(db->execute(std::move(sql)));
    if(update.has_value())
    {
        ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
            "UPDATE Posts SET update_time = ? WHERE id = ?;"));
        DO_OR_RETURN(sql.bind(mw::timeToSeconds(*update), id));
        DO_OR_RETURN(db->execute(std::move(sql)));
    }
    return {};
}

mw::E<void> DataSourceSqlite::setSchemaVersion(int64_t v) const
{
    return db->execute(std::format("PRAGMA user_version = {};", v));
}

mw::E<std::vector<Post>> DataSourceSqlite::filterPosts(std::string_view sql_suffix)
    const
{
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        std::format("SELECT id, markup, title, abstract, content, publish_time, "
                    "update_time, language, author FROM Posts {};", sql_suffix)));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int, int, std::string, std::string,
                                 std::string, int64_t, int64_t, std::string,
                                 std::string>(std::move(sql))));
    // Converting rows to post objects.
    std::vector<Post> posts;
    posts.reserve(rows.size());
    for(auto& row: rows)
    {
        ASSIGN_OR_RETURN(Post p, postFromRow(row));
        posts.push_back(std::move(p));
    }
    return posts;
}

mw::E<std::optional<nlohmann::json>> DataSourceSqlite::getValue(
    const std::string& key) const
{
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "SELECT value FROM KeyValues WHERE key = ?;"));
    DO_OR_RETURN(sql.bind(key));
    ASSIGN_OR_RETURN(auto rows, (db->eval<std::string>(std::move(sql))));
    if(rows.empty())
    {
        return std::nullopt;
    }
    nlohmann::json v = parseJSON(std::get<0>(rows[0]));
    if(v.is_discarded())
    {
        return std::unexpected(mw::runtimeError("Invalid JSON value"));
    }
    return v;
}

mw::E<void> DataSourceSqlite::setValue(const std::string& key,
                                   nlohmann::json&& value) const
{
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "INSERT INTO KeyValues (key, value) VALUES (?, ?) ON CONFLICT DO "
        "UPDATE SET value = ?;"));
    std::string v = value.dump();
    DO_OR_RETURN(sql.bind(key, v, v));
    DO_OR_RETURN(db->execute(std::move(sql)));
    if(db->changedRowsCount() != 1)
    {
        return std::unexpected(mw::runtimeError("Failed to set value."));
    }
    return {};
}

mw::E<mw::Time> DataSourceSqlite::getLatestUpdateTime() const
{
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, int64_t>(
        "SELECT publish_time, update_time FROM Posts;")));
    int64_t max_time = 0;
    for(const auto& row: rows)
    {
        if(std::get<0>(row) > max_time)
        {
            max_time = std::get<0>(row);
        }
        if(std::get<1>(row) > max_time)
        {
            max_time = std::get<1>(row);
        }
    }
    return mw::secondsToTime(max_time);
}
