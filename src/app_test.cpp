#include "gmock/gmock.h"
#include <httplib.h>
#include <memory>

#include <gtest/gtest.h>

#include "app.hpp"
#include "auth.hpp"
#include "config.hpp"
#include "auth_mock.hpp"
#include "data_mock.hpp"
#include "http_client.hpp"
#include "test_utils.hpp"
#include "utils.hpp"

using ::testing::Return;
using ::testing::HasSubstr;

class UserAppTest : public testing::Test
{
protected:
    UserAppTest()
    {
        config.base_url = "http://localhost:8080/blog";
        config.listen_address = "localhost";
        config.listen_port = 8080;
        config.data_dir = ".";
        config.blog_title = "Test Blog";

        auto auth = std::make_unique<AuthMock>();

        UserInfo expected_user;
        expected_user.name = "mw";
        Tokens token;
        token.access_token = "aaa";
        EXPECT_CALL(*auth, getUser(std::move(token)))
            .Times(::testing::AtLeast(0))
            .WillOnce(Return(expected_user));
        auto data = std::make_unique<DataSourceMock>();
        data_source = data.get();

        app = std::make_unique<App>(config, std::move(auth), std::move(data));
    }

    Configuration config;
    std::unique_ptr<App> app;
    const DataSourceMock* data_source;
};

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

TEST_F(UserAppTest, CanStart)
{
    app->start();
    app->stop();
    app->wait();
}

TEST_F(UserAppTest, CanHandleIndex)
{
    EXPECT_CALL(*data_source, getPostExcerpts())
        .WillOnce(Return(std::vector<Post>()));

    httplib::Request req;
    req.set_header("Cookie", "access-token=aaa");
    httplib::Response res;
    app->handleIndex(req, res);
    // httplib::Response::status is default to -1. Httplib will set it
    // when sending the response.
    EXPECT_EQ(res.status, -1);
    EXPECT_TRUE(res.body.contains("<title>Test Blog</title>"));
}

TEST_F(UserAppTest, CanHandleDrafts)
{
    EXPECT_CALL(*data_source, getDrafts())
        .WillOnce(Return(std::vector<Post>()));

    httplib::Request req;
    req.set_header("Cookie", "access-token=aaa");
    httplib::Response res;
    app->handleDrafts(req, res);
    EXPECT_EQ(res.status, -1);
    EXPECT_TRUE(res.body.contains("<title>Drafts</title>"));
}

TEST_F(UserAppTest, CanHandleCreatePostFrontEnd)
{
    httplib::Request req;
    req.set_header("Cookie", "access-token=aaa");
    httplib::Response res;
    app->handleCreatePostFrontEnd(req, res);
    EXPECT_EQ(res.status, -1);
    EXPECT_TRUE(res.body.contains("<title>New Post</title>"));
}

TEST_F(UserAppTest, CanHandleCreateDraft)
{
    Post p;
    p.title = "aaa";
    p.abstract = "bbb";
    p.language = "ccc";
    p.markup = Post::COMMONMARK;
    p.raw_content = "ddd";
    p.author = "mw";
    EXPECT_CALL(*data_source, saveDraft(std::move(p))).WillOnce(Return(1));

    app->start();
    {
        HTTPSession client;
        ASSIGN_OR_FAIL(const HTTPResponse* res, client.post(
            HTTPRequest("http://localhost:8080/blog/save-draft").setPayload(
                "title=aaa&abstract=bbb&language=ccc&markup=CommonMark&"
                "content=ddd")
            .addHeader("Cookie", "access-token=aaa")
            .setContentType("application/x-www-form-urlencoded")));

        EXPECT_EQ(res->status, 302) << "Response body: " << res->payloadAsStr();
        EXPECT_EQ(res->header.at("Location"),
                  "http://localhost:8080/blog/edit-draft/1");
    }
    app->stop();
    app->wait();
}

TEST_F(UserAppTest, CanHandlePublishFromNewDraft)
{
    Post p;
    p.title = "aaa";
    p.abstract = "bbb";
    p.language = "ccc";
    p.markup = Post::COMMONMARK;
    p.raw_content = "ddd";
    p.author = "mw";
    EXPECT_CALL(*data_source, saveDraft(std::move(p))).WillOnce(Return(1));
    EXPECT_CALL(*data_source, publishPost(1)).WillOnce(Return(E<void>()));

    app->start();
    {
        HTTPSession client;
        ASSIGN_OR_FAIL(const HTTPResponse* res, client.post(
            HTTPRequest("http://localhost:8080/blog/publish-from-new-draft")
            .setPayload(
                "title=aaa&abstract=bbb&language=ccc&markup=CommonMark&"
                "content=ddd")
            .addHeader("Cookie", "access-token=aaa")
            .setContentType("application/x-www-form-urlencoded")));

        EXPECT_EQ(res->status, 302) << "Response body: " << res->payloadAsStr();
        EXPECT_EQ(res->header.at("Location"),
                  "http://localhost:8080/blog/p/1");
    }
    app->stop();
    app->wait();
}

TEST_F(UserAppTest, CanHandlePost)
{
    Post p;
    p.title = "aaa";
    p.abstract = "bbb";
    p.language = "ccc";
    p.markup = Post::COMMONMARK;
    p.raw_content = "ddd {{ url_for(\"index\") }} eee";
    p.author = "mw";
    p.publish_time = Clock::now();
    p.id = 1;

    EXPECT_CALL(*data_source, getPost(1)).WillOnce(Return(p));

    app->start();
    {
        HTTPSession client;
        ASSIGN_OR_FAIL(const HTTPResponse* res,
                       client.get(HTTPRequest("http://localhost:8080/blog/p/1")
                                  .addHeader("Cookie", "access-token=aaa")));
        EXPECT_EQ(res->status, 200) << "Response body: " << res->payloadAsStr();
        EXPECT_THAT(res->payloadAsStr(), HasSubstr("<h1>aaa</h1>"));
        EXPECT_THAT(res->payloadAsStr(),
                    HasSubstr("ddd http://localhost:8080/blog eee"));
    }
    app->stop();
    app->wait();
}

TEST_F(UserAppTest, CanHandleEditPostFrontEnd)
{
    Post p;
    p.title = "aaa";
    p.abstract = "bbb";
    p.language = "ccc";
    p.markup = Post::COMMONMARK;
    p.raw_content = "ddd";
    p.author = "mw";
    p.id = 1;

    EXPECT_CALL(*data_source, getPost(1)).WillOnce(Return(p));
    app->start();
    {
        HTTPSession client;
        ASSIGN_OR_FAIL(const HTTPResponse* res, client.get(
            HTTPRequest("http://localhost:8080/blog/edit-post/1")
            .addHeader("Cookie", "access-token=aaa")));

        EXPECT_EQ(res->status, 200) << "Response body: " << res->payloadAsStr();
    }
    app->stop();
    app->wait();
}

TEST_F(UserAppTest, CanHandleSavePost)
{
    Post p;
    p.title = "aaa";
    p.abstract = "bbb";
    p.language = "ccc";
    p.markup = Post::COMMONMARK;
    p.raw_content = "ddd";
    p.author = "mw";
    p.id = 1;

    EXPECT_CALL(*data_source, updatePost(std::move(p)))
        .WillOnce(Return(E<void>()));
    app->start();
    {
        HTTPSession client;
        ASSIGN_OR_FAIL(const HTTPResponse* res, client.post(
            HTTPRequest("http://localhost:8080/blog/save-post").setPayload(
                "title=aaa&abstract=bbb&language=ccc&markup=CommonMark&"
                "content=ddd&id=1")
            .addHeader("Cookie", "access-token=aaa")
            .setContentType("application/x-www-form-urlencoded")));

        EXPECT_EQ(res->status, 302) << "Response body: " << res->payloadAsStr();
        EXPECT_EQ(res->header.at("Location"), "http://localhost:8080/blog/p/1");
    }
    app->stop();
    app->wait();
}
