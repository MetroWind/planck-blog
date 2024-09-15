#include <optional>
#include <chrono>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "attachment.hpp"
#include "data.hpp"
#include "error.hpp"
#include "utils.hpp"
#include "post.hpp"
#include "test_utils.hpp"

using ::testing::IsEmpty;

TEST(DataSource, CanPublishDraftAndDelete)
{
    ASSIGN_OR_FAIL(std::unique_ptr<DataSourceSqlite> data,
                   DataSourceSqlite::newFromMemory());
    {
        ASSIGN_OR_FAIL(std::vector<Post> ps, data->getPosts());
        EXPECT_EQ(ps.size(), 0);
    }

    Post p;
    p.markup = Post::MARKDOWN;
    p.language = "en-US";
    p.raw_content = "aaa";
    p.abstract = "bbb";
    ASSIGN_OR_FAIL(int64_t id, data->saveDraft(std::move(p)));
    {
        ASSIGN_OR_FAIL(auto ps, data->getPosts());
        EXPECT_EQ(ps.size(), 0);
    }
    {
        ASSIGN_OR_FAIL(auto ps, data->getDrafts());
        EXPECT_EQ(ps.size(), 1);
    }
    {
        ASSIGN_OR_FAIL(std::optional<Post> draft, data->getDraft(id));
        ASSERT_TRUE(draft.has_value());
    }

    ASSERT_TRUE(isExpected(data->publishPost(id)));
    // There shouldn’t be any drafts.
    {
        ASSIGN_OR_FAIL(std::optional<Post> draft, data->getDraft(id));
        ASSERT_FALSE(draft.has_value());
    }
    {
        ASSIGN_OR_FAIL(auto ps, data->getDrafts());
        EXPECT_EQ(ps.size(), 0);
    }
    int64_t post_id;
    {
        ASSIGN_OR_FAIL(std::vector<Post> ps, data->getPosts());
        EXPECT_EQ(ps.size(), 1);
        EXPECT_EQ(ps[0].language, "en-US");
        EXPECT_EQ(ps[0].raw_content, "aaa");
        EXPECT_EQ(ps[0].abstract, "bbb");
        ASSERT_TRUE(ps[0].id.has_value());
        post_id = *ps[0].id;
        ASSIGN_OR_FAIL(std::optional<Post> p, data->getPost(post_id));
        ASSERT_TRUE(p.has_value());
        EXPECT_EQ(*p, ps[0]);
    }
    {
        ASSIGN_OR_FAIL(std::vector<Post> ps, data->getPostExcerpts());
        EXPECT_EQ(ps.size(), 1);
        EXPECT_EQ(ps[0].language, "en-US");
        EXPECT_EQ(ps[0].abstract, "bbb");
    }
    {
        EXPECT_TRUE(isExpected(data->deletePost(post_id)));
        ASSIGN_OR_FAIL(std::vector<Post> ps, data->getPosts());
        EXPECT_EQ(ps.size(), 0);
    }
}

TEST(DataSource, CanAddAndDeleteAttachments)
{
    ASSIGN_OR_FAIL(std::unique_ptr<DataSourceSqlite> data,
                   DataSourceSqlite::newFromMemory());
    {
        ASSIGN_OR_FAIL(std::vector<Attachment> atts, data->getAttachments());
        EXPECT_EQ(atts.size(), 0);
    }

    Attachment att;
    att.content_type = "aaa";
    att.hash = "bbb";
    att.original_name = "ccc";
    EXPECT_TRUE(isExpected(data->addAttachment(std::move(att))));
    {
        ASSIGN_OR_FAIL(std::vector<Attachment> atts, data->getAttachments());
        ASSERT_EQ(atts.size(), 1);
        EXPECT_EQ(atts[0].content_type, "aaa");
        EXPECT_EQ(atts[0].hash, "bbb");
        EXPECT_EQ(atts[0].original_name, "ccc");
        EXPECT_GT(timeToSeconds(atts[0].upload_time), 0);
    }
    {
        ASSIGN_OR_FAIL(std::optional<Attachment> att, data->getAttachment("bbb"));
        ASSERT_TRUE(att.has_value());
        EXPECT_EQ(att->content_type, "aaa");
        EXPECT_EQ(att->hash, "bbb");
        EXPECT_EQ(att->original_name, "ccc");
        EXPECT_GT(timeToSeconds(att->upload_time), 0);
    }
    {
        EXPECT_TRUE(isExpected(data->deleteAttachment("bbb")));
        ASSIGN_OR_FAIL(std::vector<Attachment> atts, data->getAttachments());
        ASSERT_EQ(atts.size(), 0);
    }
}

TEST(DataSource, CanGetSchemaVesrion)
{
    ASSIGN_OR_FAIL(std::unique_ptr<DataSourceSqlite> data,
                   DataSourceSqlite::newFromMemory());
    ASSIGN_OR_FAIL(int64_t v, data->getSchemaVersion());
    EXPECT_GT(v, 0);
}

TEST(DataSource, CanAddAttachmentReferral)
{
    ASSIGN_OR_FAIL(std::unique_ptr<DataSourceSqlite> data,
                   DataSourceSqlite::newFromMemory());
    Attachment att;
    att.content_type = "aaa";
    att.hash = "bbb";
    att.original_name = "ccc";
    EXPECT_TRUE(isExpected(data->addAttachment(std::move(att))));
    {
        ASSIGN_OR_FAIL(auto refs, data->getReferralsOfAttachment("bbb"));
        EXPECT_TRUE(refs.empty());
    }
    {
        EXPECT_TRUE(isExpected(data->addAttachmentReferral("bbb", "zzz")));
        EXPECT_TRUE(isExpected(data->addAttachmentReferral("bbb", "yyy")));
        EXPECT_TRUE(isExpected(data->addAttachmentReferral("bbb", "zzz")));
        ASSIGN_OR_FAIL(auto refs, data->getReferralsOfAttachment("bbb"));
        DataSourceInterface::ReferralCounts expected;
        expected["zzz"] = 2;
        expected["yyy"] = 1;
        EXPECT_EQ(refs, expected);
    }
}
