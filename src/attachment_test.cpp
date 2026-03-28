#include <gtest/gtest.h>
#include <mw/crypto_mock.hpp>

#include "attachment.hpp"

using ::testing::Return;

TEST(Attachment, CanGetObjectFromBytesAndGetPath)
{
    mw::HasherMock hasher;
    AttachmentManager m(hasher);
    EXPECT_CALL(hasher, hashToBytes("aaa"))
        .WillOnce(Return(std::vector<unsigned char>{0xab, 0xcd}));
    Attachment att = m.attachmentFromBytes("aaa", "aaa.txt");
    EXPECT_EQ(att.hash, "abcd");
    EXPECT_EQ(att.original_name, "aaa.txt");
    EXPECT_EQ(att.content_type, "text/plain");
    EXPECT_EQ(m.path(att), "a/abcd.txt");
}
