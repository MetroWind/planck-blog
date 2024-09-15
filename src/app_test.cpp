#include <httplib.h>
#include <memory>

#include <gtest/gtest.h>

#include "app.hpp"
#include "auth.hpp"
#include "config.hpp"
#include "auth_mock.hpp"
#include "data.hpp"
#include "http_client.hpp"
#include "test_utils.hpp"

using ::testing::Return;
using ::testing::HasSubstr;

TEST(App, CopyReqToHttplibReq)
{
    {
        auto req = HTTPRequest("http://test/").setPayload("aaa")
            .setContentType("text/plain").addHeader("X-Something", "something");
        httplib::Request http_req;
        copyToHttplibReq(req, http_req);
        EXPECT_EQ(http_req.body, "aaa");
        EXPECT_EQ(http_req.get_header_value("Content-Type"), "text/plain");
        EXPECT_EQ(http_req.get_header_value("X-Something"), "something");
    }
    {
        auto req = HTTPRequest("http://test/").setContentType("image/png");
        httplib::Request http_req;
        copyToHttplibReq(req, http_req);
        EXPECT_EQ(http_req.get_header_value("Content-Type"), "image/png");
    }
}

TEST(App, IndexCanRefreshToken)
{
    Configuration config;
    Tokens expected_tokens_after_refresh;
    expected_tokens_after_refresh.access_token = "aaa";
    UserInfo expected_user;
    expected_user.name = "mw";

    auto auth = std::make_unique<AuthMock>();
    EXPECT_CALL(*auth, getUser(expected_tokens_after_refresh))
        .WillOnce(Return(expected_user));
    EXPECT_CALL(*auth, refreshTokens("bbb"))
        .WillOnce(Return(expected_tokens_after_refresh));

    ASSIGN_OR_FAIL(auto data, DataSourceSqlite::newFromMemory());
    App app(config, std::move(auth), std::move(data));

    httplib::Request req;
    req.set_header("Cookie", "refresh-token=bbb");
    httplib::Response res;
    app.handleIndex(req, res);
    EXPECT_EQ(res.status, 302);
    EXPECT_THAT(res.get_header_value("Set-Cookie"),
                HasSubstr("access-token=aaa"));
    EXPECT_EQ(res.get_header_value("Location"), app.urlFor("weekly", "mw"));
}

TEST(App, LoginBringsUserToLoginURL)
{
    Configuration config;
    auto auth = std::make_unique<AuthMock>();
    EXPECT_CALL(*auth, initialURL()).WillOnce(Return("http://aaa/"));
    ASSIGN_OR_FAIL(auto data, DataSourceSqlite::newFromMemory());
    App app(config, std::move(auth), std::move(data));

    httplib::Response res;
    app.handleLogin(res);
    EXPECT_EQ(res.status, 301);
    EXPECT_EQ(res.get_header_value("Location"), "http://aaa/");
}

TEST(App, CanHandleOpenIDRedirect)
{
    Configuration config;
    auto auth = std::make_unique<AuthMock>();
    Tokens expected_tokens;
    expected_tokens.access_token = "bbb";
    UserInfo expected_user;
    expected_user.name = "mw";

    EXPECT_CALL(*auth, authenticate("aaa")).WillOnce(Return(expected_tokens));
    EXPECT_CALL(*auth, getUser(expected_tokens)).WillOnce(Return(expected_user));
    ASSIGN_OR_FAIL(auto data, DataSourceSqlite::newFromMemory());
    App app(config, std::move(auth), std::move(data));

    httplib::Request req;
    req.params.emplace("code", "aaa");
    httplib::Response res;
    app.handleOpenIDRedirect(req, res);
    EXPECT_EQ(res.status, 301);
    EXPECT_EQ(res.get_header_value("Location"), app.urlFor("index", ""));
}

TEST(App, OpenIDRedirectCanHandleUpstreamError)
{
    Configuration config;
    auto auth = std::make_unique<AuthMock>();
    ASSIGN_OR_FAIL(auto data, DataSourceSqlite::newFromMemory());
    App app(config, std::move(auth), std::move(data));
    {
        httplib::Request req;
        req.params.emplace("error", "aaa");
        httplib::Response res;
        app.handleOpenIDRedirect(req, res);
        EXPECT_EQ(res.status, 500);
    }
    {
        httplib::Request req;
        httplib::Response res;
        app.handleOpenIDRedirect(req, res);
        EXPECT_EQ(res.status, 500);
    }
}
