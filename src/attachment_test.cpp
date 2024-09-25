#include <gtest/gtest.h>

#include "attachment.hpp"
#include "hash_mock.hpp"

using ::testing::Return;

TEST(Attachment, CanGetObjectFromBytesAndGetPath)
{
    HasherMock hasher;
    AttachmentManager m(hasher);
    EXPECT_CALL(hasher, hashToHexStr("aaa")).WillOnce(Return("xyz"));
    Attachment att = m.attachmentFromBytes("aaa", "aaa.txt");
    EXPECT_EQ(att.hash, "xyz");
    EXPECT_EQ(att.original_name, "aaa.txt");
    EXPECT_EQ(att.content_type, "text/plain");
    EXPECT_EQ(m.path(att), "x/xyz.txt");
}
