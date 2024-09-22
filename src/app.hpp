#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <string_view>
#include <format>
#include <optional>

#include <httplib.h>
#include <spdlog/spdlog.h>
#include <inja.hpp>

#include "auth.hpp"
#include "config.hpp"
#include "data.hpp"
#include "http_client.hpp"
#include "utils.hpp"
#include "url.hpp"
#include "post_rendering.hpp"

void copyToHttplibReq(const HTTPRequest& src, httplib::Request& dest);

class App
{
public:
    App() = delete;
    App(const Configuration& conf,
        std::unique_ptr<AuthInterface> openid_auth,
        std::unique_ptr<DataSourceInterface> data_source);

    std::string urlFor(const std::string& name, const std::string& arg="") const;

    void handleIndex(const httplib::Request& req, httplib::Response& res);
    void handleLogin(httplib::Response& res) const;
    void handleOpenIDRedirect(const httplib::Request& req,
                              httplib::Response& res) const;
    void handleDrafts(const httplib::Request& req, httplib::Response& res);
    void handleCreatePostFrontEnd(const httplib::Request& req, httplib::Response& res);
    void handleCreateDraft(const httplib::Request& req, httplib::Response& res) const;

    void start();
    void stop();
    void wait();

private:
    struct SessionValidation
    {
        enum { VALID, REFRESHED, INVALID } status;
        UserInfo user;
        Tokens new_tokens;

        static SessionValidation valid(UserInfo&& user_info)
        {
            return {VALID, user_info, {}};
        }

        static SessionValidation refreshed(UserInfo&& user_info, Tokens&& tokens)
        {
            return {REFRESHED, user_info, tokens};
        }

        static SessionValidation invalid()
        {
            return {INVALID, {}, {}};
        }
    };
    E<SessionValidation> validateSession(const httplib::Request& req) const;
    std::optional<SessionValidation> ensureSession(
        const httplib::Request& req, httplib::Response& res) const;

    E<nlohmann::json> renderPostToJson(const Post& p);

    // This gives a path, optionally with the name of an argument,
    // that is suitable to bind to a URL handler. For example,
    // supposed the URL of the blog post with ID 1 is
    // “http://some.domain/blog/p/1”. Calling “getPath("post", "id")”
    // would give “/blog/p/:id”. This uses urlFor(), and therefore
    // requires that the URL is mapped correctly in that function.
    std::string getPath(const std::string& name, const std::string& arg_name="")
        const;
    const Configuration config;
    inja::Environment templates;
    std::unique_ptr<AuthInterface> auth;
    std::unique_ptr<DataSourceInterface> data;
    PostCache post_cache;
    URL base_url;
    std::atomic<bool> should_stop;
    std::thread server_thread;
    httplib::Server server;
};
