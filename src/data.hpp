#pragma once

#include <memory>
#include <vector>
#include <string>
#include <string_view>
#include <optional>
#include <unordered_map>

#include <sqlite3.h>

#include "attachment.hpp"
#include "database.hpp"
#include "post.hpp"
#include "error.hpp"

class DataSourceInterface
{
public:
    using ReferralCounts = std::unordered_map<std::string, int64_t>;

    virtual ~DataSourceInterface() = default;
    // The schema version is the version of the database. It starts
    // from 1. Every time the schema change, someone should increase
    // this number by 1, manually, by hand. The intended use is to
    // help with database migration.
    virtual E<int64_t> getSchemaVersion() const = 0;

    // Get all published posts, newest first.
    virtual E<std::vector<Post>> getPosts() const = 0;
    // Get one post by ID.
    virtual E<std::optional<Post>> getPost(int64_t id) const = 0;
    // Get the ID, title, abstract, and language of all published
    // posts, newest first.
    virtual E<std::vector<Post>> getPostExcerpts() const = 0;

    // Update an existing post. The reason this (and saveDraft())
    // takes an rvalue is that the post will acquire a new update
    // time, and thus invalidate the post object, meaning the post
    // object is no longer correct.
    virtual E<void> updatePost(Post&& new_post) const = 0;
    // Create a new draft. A draft is just a post with a zero publish
    // time.
    virtual E<int64_t> saveDraft(Post&& new_post) const = 0;
    // Get all drafts in no particular order.
    virtual E<std::vector<Post>> getDrafts() const = 0;
    // Get one draft by ID.
    virtual E<std::optional<Post>> getDraft(int64_t id) const = 0;
    // Update an existing draft.
    virtual E<void> editDraft(const Post& draft) const = 0;
    // Publish a draft with “id” into a post. This just changes the
    // update time to current time.
    virtual E<void> publishPost(int64_t id) const = 0;
    // Delete a post or draft by ID.
    virtual E<void> deletePost(int64_t id) const = 0;

    // Add an attachment. If the hash already exists, do nothing and
    // return void.
    virtual E<void> addAttachment(Attachment&& att) const = 0;
    // Get one attachment by hash.
    virtual E<std::optional<Attachment>>
    getAttachment(const std::string& hash) const = 0;
    // Get all attachments in no particular order.
    virtual E<std::vector<Attachment>> getAttachments() const = 0;
    // Delete an attachment by hash.
    virtual E<void> deleteAttachment(const std::string& hash) const = 0;
    // Get all referrals of an attachment.
    virtual E<ReferralCounts> getReferralsOfAttachment(const std::string& hash)
        const = 0;
    // Increase the request count of an attachment from a specific URL
    // by one. If there is no such referral, set the count to one.
    virtual E<void> addAttachmentReferral(const std::string& attachment_hash,
                                          const std::string& url) const = 0;

protected:
    virtual E<void> setSchemaVersion(int64_t v) const = 0;

};

class DataSourceSqlite : public DataSourceInterface
{
public:
    explicit DataSourceSqlite(std::unique_ptr<SQLite> conn)
            : db(std::move(conn)) {}

    ~DataSourceSqlite() override = default;
    DataSourceSqlite(const DataSourceSqlite&) = delete;
    DataSourceSqlite& operator=(const DataSourceSqlite&) = delete;

    static E<std::unique_ptr<DataSourceSqlite>>
    fromFile(const std::string& db_file);
    static E<std::unique_ptr<DataSourceSqlite>> newFromMemory();

    // We use the user_version pragma for the schema version. In
    // SQLite this is only 32 bits.
    E<int64_t> getSchemaVersion() const override;

    E<std::vector<Post>> getPosts() const override;
    E<std::vector<Post>> getPostExcerpts() const override;
    E<std::optional<Post>> getPost(int64_t id) const override;
    E<void> updatePost(Post&& new_post) const override;
    E<int64_t> saveDraft(Post&& new_post) const override;
    E<std::vector<Post>> getDrafts() const override;
    E<std::optional<Post>> getDraft(int64_t id) const override;
    E<void> editDraft(const Post& draft) const override;
    E<void> publishPost(int64_t id) const override;
    E<void> deletePost(int64_t id) const override;
    E<void> addAttachment(Attachment&& att) const override;
    E<std::optional<Attachment>> getAttachment(const std::string& hash)
        const override;
    E<std::vector<Attachment>> getAttachments() const override;
    E<void> deleteAttachment(const std::string& hash) const override;
    E<ReferralCounts> getReferralsOfAttachment(const std::string& hash)
        const override;
    E<void> addAttachmentReferral(const std::string& attachment_hash,
                                  const std::string& url) const override;

    E<void> forceSetPostTimes(int64_t id, const Time& publish,
                              const std::optional<Time>& update) const;
    // Do not use.
    DataSourceSqlite() = default;

protected:
    E<void> setSchemaVersion(int64_t v) const override;

private:
    std::unique_ptr<SQLite> db;

    E<std::vector<Post>> filterPosts(std::string_view sql_suffix) const;
};
