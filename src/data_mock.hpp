#pragma once

#include <optional>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <mw/error.hpp>

#include "attachment.hpp"
#include "data.hpp"
#include "post.hpp"

class DataSourceMock : public DataSourceInterface
{
public:
    ~DataSourceMock() override = default;

    MOCK_METHOD(mw::E<int64_t>, getSchemaVersion, (), (const override));
    MOCK_METHOD(mw::E<std::vector<Post>>, getPosts, (), (const override));
    MOCK_METHOD(mw::E<std::vector<Post>>, getPosts, (int start, int count),
                (const override));
    MOCK_METHOD(mw::E<std::vector<Post>>, getPostExcerpts, (),
                (const override));
    MOCK_METHOD(mw::E<std::optional<Post>>, getPost, (int64_t id),
                (const override));
    MOCK_METHOD(mw::E<void>, updatePost, (Post && new_post), (const override));
    MOCK_METHOD(mw::E<void>, updatePostNoUpdateTime, (const Post& new_post),
                (const override));
    MOCK_METHOD(mw::E<int64_t>, saveDraft, (Post && new_post),
                (const override));
    MOCK_METHOD(mw::E<std::vector<Post>>, getDrafts, (), (const override));
    MOCK_METHOD(mw::E<std::optional<Post>>, getDraft, (int64_t id),
                (const override));
    MOCK_METHOD(mw::E<void>, editDraft, (const Post& draft), (const override));
    MOCK_METHOD(mw::E<void>, publishPost, (int64_t id), (const override));
    MOCK_METHOD(mw::E<void>, deletePost, (int64_t id), (const override));
    MOCK_METHOD(mw::E<void>, addAttachment, (Attachment && att),
                (const override));
    MOCK_METHOD(mw::E<std::optional<Attachment>>, getAttachment,
                (const std::string& hash), (const override));
    MOCK_METHOD(mw::E<std::vector<Attachment>>, getAttachments, (),
                (const override));
    MOCK_METHOD(mw::E<void>, deleteAttachment, (const std::string& hash),
                (const override));
    MOCK_METHOD(mw::E<ReferralCounts>, getReferralsOfAttachment,
                (const std::string& hash), (const override));
    MOCK_METHOD(mw::E<void>, addAttachmentReferral,
                (const std::string& attachment_hash, const std::string& url),
                (const override));
    MOCK_METHOD(mw::E<std::optional<nlohmann::json>>, getValue,
                (const std::string& key), (const override));
    MOCK_METHOD(mw::E<void>, setValue,
                (const std::string& key, nlohmann::json&& value),
                (const override));
    MOCK_METHOD(mw::E<mw::Time>, getLatestUpdateTime, (), (const override));

protected:
    mw::E<void> setSchemaVersion([[maybe_unused]] int64_t v) const override
    {
        return {};
    }
};
