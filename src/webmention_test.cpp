#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mw/http_client_mock.hpp>

#include "data_mock.hpp"
#include "webmention.hpp"

using ::testing::_;
using ::testing::Field;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrictMock;

namespace
{

// Helper to create a WebMentionManager with a specific mock session behavior
template <typename F>
WebMentionManager createManager(DataSourceInterface& data, F&& factory_logic,
                                bool allow_internal = false)
{
    return WebMentionManager(
        data,
        [logic = std::forward<F>(factory_logic)]() mutable
        {
            auto mock = std::make_unique<StrictMock<mw::HTTPSessionMock>>();
            logic(*mock);
            return mock;
        },
        allow_internal);
}

} // namespace

TEST(WebMention, VerifyWebMentionDropsSSRF)
{
    StrictMock<DataSourceMock> data_mock;
    auto wm = createManager(data_mock, [](mw::HTTPSessionMock&) {});

    EXPECT_CALL(data_mock, deleteWebMention(1)).WillOnce(Return(mw::E<void>{}));
    wm.verifyWebMentionSync(1, "http://127.0.0.1/admin", "http://target.com");

    EXPECT_CALL(data_mock, deleteWebMention(2)).WillOnce(Return(mw::E<void>{}));
    wm.verifyWebMentionSync(2, "http://localhost:8080/foo",
                            "http://target.com");
}

TEST(WebMention, VerifyWebMentionDrops404)
{
    StrictMock<DataSourceMock> data_mock;
    auto wm = createManager(
        data_mock,
        [](mw::HTTPSessionMock& mock)
        {
            EXPECT_CALL(mock, maxRedirections(20))
                .WillOnce(Return(mw::E<void>{}));
            EXPECT_CALL(mock, transferTimeout(_))
                .WillOnce(Return(mw::E<void>{}));
            EXPECT_CALL(mock, maxSize(_)).WillOnce(Return(mw::E<void>{}));
            EXPECT_CALL(mock, get(_))
                .WillOnce(Invoke(
                    [](const mw::HTTPRequest&) -> mw::E<const mw::HTTPResponse*>
                    {
                        static mw::HTTPResponse res;
                        res.status = 404;
                        return &res;
                    }));
        });

    EXPECT_CALL(data_mock, deleteWebMention(1)).WillOnce(Return(mw::E<void>{}));
    wm.verifyWebMentionSync(1, "http://source.com/404", "http://target.com");
}

TEST(WebMention, VerifyWebMentionAllowsSSRFIfConfigured)
{
    StrictMock<DataSourceMock> data_mock;
    auto wm = createManager(
        data_mock,
        [](mw::HTTPSessionMock& mock)
        {
            EXPECT_CALL(mock, maxRedirections(20))
                .WillOnce(Return(mw::E<void>{}));
            EXPECT_CALL(mock, transferTimeout(_))
                .WillOnce(Return(mw::E<void>{}));
            EXPECT_CALL(mock, maxSize(_)).WillOnce(Return(mw::E<void>{}));
            EXPECT_CALL(mock, get(_))
                .WillOnce(Invoke(
                    [](const mw::HTTPRequest&) -> mw::E<const mw::HTTPResponse*>
                    {
                        static mw::HTTPResponse res;
                        res.status = 404;
                        return &res;
                    }));
        },
        true); // allow_internal = true

    EXPECT_CALL(data_mock, deleteWebMention(1)).WillOnce(Return(mw::E<void>{}));
    wm.verifyWebMentionSync(1, "http://127.0.0.1/admin", "http://target.com");
}

TEST(WebMention, VerifyWebMentionValidHtml)
{
    StrictMock<DataSourceMock> data_mock;
    auto wm = createManager(
        data_mock,
        [](mw::HTTPSessionMock& mock)
        {
            EXPECT_CALL(mock, maxRedirections(20))
                .WillOnce(Return(mw::E<void>{}));
            EXPECT_CALL(mock, transferTimeout(_))
                .WillOnce(Return(mw::E<void>{}));
            EXPECT_CALL(mock, maxSize(_)).WillOnce(Return(mw::E<void>{}));
            EXPECT_CALL(mock, get(_))
                .WillOnce(Invoke(
                    [](const mw::HTTPRequest&) -> mw::E<const mw::HTTPResponse*>
                    {
                        static mw::HTTPResponse res;
                        res.status = 200;
                        res.header["Content-Type"] = "text/html";
                        std::string body = "<html><body><p>Hello <a "
                                           "href=\"http://target.com\">link</"
                                           "a></p></body></html>";
                        res.payload = std::vector<std::byte>(
                            reinterpret_cast<const std::byte*>(body.data()),
                            reinterpret_cast<const std::byte*>(body.data() +
                                                               body.size()));
                        return &res;
                    }));
        });

    EXPECT_CALL(data_mock,
                updateWebMention(1, 1, _, _, testing::Ne(std::nullopt)))
        .WillOnce(Return(mw::E<void>{}));

    wm.verifyWebMentionSync(1, "http://source.com/valid", "http://target.com");
}

TEST(WebMention, SendWebMentionsDiscoverFromHeaderAndPost)
{
    StrictMock<DataSourceMock> data_mock;
    auto shared_mock = std::make_shared<StrictMock<mw::HTTPSessionMock>>();

    EXPECT_CALL(*shared_mock,
                get(Field(&mw::HTTPRequest::url, "http://target.com/page")))
        .WillOnce(Invoke(
            [](const mw::HTTPRequest&) -> mw::E<const mw::HTTPResponse*>
            {
                static mw::HTTPResponse res;
                res.status = 200;
                res.header["Link"] =
                    "<http://target.com/webmention>; rel=\"webmention\"";
                return &res;
            }));

    EXPECT_CALL(*shared_mock, post(Field(&mw::HTTPRequest::url,
                                         "http://target.com/webmention")))
        .WillOnce(Invoke(
            [](const mw::HTTPRequest&) -> mw::E<const mw::HTTPResponse*>
            {
                static mw::HTTPResponse res;
                res.status = 202;
                return &res;
            }));

    WebMentionManager wm(
        data_mock,
        [shared_mock]() -> std::unique_ptr<mw::HTTPSessionInterface>
        {
            class MockWrapper : public mw::HTTPSessionInterface
            {
                std::shared_ptr<mw::HTTPSessionMock> mock_;

            public:
                MockWrapper(std::shared_ptr<mw::HTTPSessionMock> m) : mock_(m)
                {
                }
                mw::E<const mw::HTTPResponse*>
                get(const mw::HTTPRequest& req) override
                {
                    return mock_->get(req);
                }
                mw::E<const mw::HTTPResponse*>
                post(const mw::HTTPRequest& req) override
                {
                    return mock_->post(req);
                }
                std::chrono::duration<long> transferTimeout() const override
                {
                    return std::chrono::duration<long>(0);
                }
                mw::E<void>
                transferTimeout(std::chrono::duration<long>) override
                {
                    return {};
                }
                std::chrono::duration<long> connectionTimeout() const override
                {
                    return std::chrono::duration<long>(60);
                }
                mw::E<void>
                connectionTimeout(std::chrono::duration<long>) override
                {
                    return {};
                }
                long maxSize() const override
                {
                    return 2147483648;
                }
                mw::E<void> maxSize(long) override
                {
                    return {};
                }
                long maxRedirections() const override
                {
                    return 20;
                }
                mw::E<void> maxRedirections(long) override
                {
                    return {};
                }
            };
            return std::make_unique<MockWrapper>(shared_mock);
        });

    wm.sendWebMentionsSync("http://myblog.com/post/1",
                           {"http://target.com/page"});
}

namespace
{

// Reusable wrapper that delegates get/post to a shared mock and
// returns success for all option setters. Lets a single
// HTTPSessionMock back many sessions created by the factory.
class SessionWrapper : public mw::HTTPSessionInterface
{
public:
    explicit SessionWrapper(std::shared_ptr<mw::HTTPSessionMock> m)
        : mock_(std::move(m))
    {
    }
    mw::E<const mw::HTTPResponse*> get(const mw::HTTPRequest& req) override
    {
        return mock_->get(req);
    }
    mw::E<const mw::HTTPResponse*> post(const mw::HTTPRequest& req) override
    {
        return mock_->post(req);
    }
    std::chrono::duration<long> transferTimeout() const override
    {
        return std::chrono::duration<long>(0);
    }
    mw::E<void> transferTimeout(std::chrono::duration<long>) override
    {
        return {};
    }
    std::chrono::duration<long> connectionTimeout() const override
    {
        return std::chrono::duration<long>(60);
    }
    mw::E<void> connectionTimeout(std::chrono::duration<long>) override
    {
        return {};
    }
    long maxSize() const override { return 2147483648; }
    mw::E<void> maxSize(long) override { return {}; }
    long maxRedirections() const override { return 0; }
    mw::E<void> maxRedirections(long) override { return {}; }

private:
    std::shared_ptr<mw::HTTPSessionMock> mock_;
};

} // namespace

TEST(WebMention, SendWebMentionsFollowsRedirectAndResolvesRelativeEndpoint)
{
    StrictMock<DataSourceMock> data_mock;
    auto shared_mock = std::make_shared<StrictMock<mw::HTTPSessionMock>>();

    // Hop 0: original target redirects to a new path on a different
    // host using a relative-looking absolute-path Location.
    EXPECT_CALL(*shared_mock,
                get(Field(&mw::HTTPRequest::url, "http://target.com/page")))
        .WillOnce(Invoke(
            [](const mw::HTTPRequest&) -> mw::E<const mw::HTTPResponse*>
            {
                static mw::HTTPResponse res;
                res.status = 301;
                res.header.clear();
                res.header["Location"] = "https://new.example/blog/p/42";
                return &res;
            }));

    // Hop 1: final page advertises a *relative* webmention endpoint
    // via Link header. The endpoint path includes a query string that
    // must be preserved.
    EXPECT_CALL(*shared_mock, get(Field(&mw::HTTPRequest::url,
                                        "https://new.example/blog/p/42")))
        .WillOnce(Invoke(
            [](const mw::HTTPRequest&) -> mw::E<const mw::HTTPResponse*>
            {
                static mw::HTTPResponse res;
                res.status = 200;
                res.payload.clear();
                res.header.clear();
                res.header["Link"] =
                    "</wm?token=abc>; rel=\"webmention\"";
                return &res;
            }));

    // The endpoint must be resolved against the *final* URL after
    // following the redirect, not the original target. So the POST
    // goes to https://new.example/wm?token=abc.
    EXPECT_CALL(*shared_mock, post(Field(&mw::HTTPRequest::url,
                                         "https://new.example/wm?token=abc")))
        .WillOnce(Invoke(
            [](const mw::HTTPRequest&) -> mw::E<const mw::HTTPResponse*>
            {
                static mw::HTTPResponse res;
                res.status = 202;
                return &res;
            }));

    WebMentionManager wm(
        data_mock,
        [shared_mock]() -> std::unique_ptr<mw::HTTPSessionInterface>
        { return std::make_unique<SessionWrapper>(shared_mock); });

    wm.sendWebMentionsSync("http://myblog.com/post/1",
                           {"http://target.com/page"});
}
