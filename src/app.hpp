#pragma once

#include <atomic>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <httplib.h>
#include <spdlog/spdlog.h>
#include <inja.hpp>

#include "attachment.hpp"
#include <mw/auth.hpp>
#include "config.hpp"
#include "data.hpp"
#include <mw/crypto.hpp>
#include <mw/http_client.hpp>
#include "post_rendering.hpp"
#include "theme.hpp"
#include <mw/url.hpp>
#include <mw/utils.hpp>

void copyToHttplibReq(const mw::HTTPRequest& src, httplib::Request& dest);

class App
{
public:
    App() = delete;
    App(const Configuration& conf,
        std::unique_ptr<mw::AuthInterface> openid_auth,
        std::unique_ptr<DataSourceInterface> data_source);

    std::string urlFor(const std::string& name, const std::string& arg="") const;

    void handleIndex(const httplib::Request& req, httplib::Response& res);
    void handleLogin(httplib::Response& res) const;
    void handleOpenIDRedirect(const httplib::Request& req,
                              httplib::Response& res) const;
    void handlePost(const httplib::Request& req, httplib::Response& res);
    void handleDrafts(const httplib::Request& req, httplib::Response& res);
    void handleCreatePostFrontEnd(const httplib::Request& req,
                                  httplib::Response& res);
    void handleSaveDraft(const httplib::Request& req, httplib::Response& res)
        const;
    void handleEditDraftFrontEnd(const httplib::Request& req,
                                 httplib::Response& res);
    void handleEditPostFrontEnd(const httplib::Request& req,
                                httplib::Response& res);
    void handleSavePost(const httplib::Request& req, httplib::Response& res)
        const;
    void handlePublishFromDraft(const httplib::Request& req,
                                httplib::Response& res) const;
    void handleAttachments(const httplib::Request& req, httplib::Response& res);
    void handleAttachment(const httplib::Request& req, httplib::Response& res);
    void handleAttachmentUpload(const httplib::Request& req,
                                httplib::Response& res) const;
    void handleSelectTheme(const httplib::Request& req, httplib::Response& res)
        const;
    void handleFeed(const httplib::Request& req, httplib::Response& res);

    void start();
    void stop();
    void wait();

private:
    struct SessionValidation
    {
        enum { VALID, REFRESHED, INVALID } status;
        mw::UserInfo user;
        mw::Tokens new_tokens;

        static SessionValidation valid(mw::UserInfo&& user_info)
        {
            return {VALID, user_info, {}};
        }

        static SessionValidation refreshed(mw::UserInfo&& user_info, mw::Tokens&& tokens)
        {
            return {REFRESHED, user_info, tokens};
        }

        static SessionValidation invalid()
        {
            return {INVALID, {}, {}};
        }
    };
    mw::E<SessionValidation> validateSession(const httplib::Request& req) const;

    // Query the auth module for the status of the session. If there
    // is no session or it fails to query the auth module, set the
    // status and body in “res” accordingly. If
    // “allow_error_and_invalid” is true, failure to query and invalid
    // session are considered ok, and no status and body would be set
    // in “res”. In this case this function just returns an invalid
    // session.
    std::optional<SessionValidation> prepareSession(
        const httplib::Request& req, httplib::Response& res,
        bool allow_error_and_invalid=false) const;

    nlohmann::json postToJson(const Post& p) const;
    mw::E<nlohmann::json> renderPostToJson(Post&& p, bool use_cache=true);

    // This gives a path, optionally with the name of an argument,
    // that is suitable to bind to a mw::URL handler. For example,
    // supposed the mw::URL of the blog post with ID 1 is
    // “http://some.domain/blog/p/1”. Calling “getPath("post", "id")”
    // would give “/blog/p/:id”. This uses urlFor(), and therefore
    // requires that the mw::URL is mapped correctly in that function.
    std::string getPath(const std::string& name, const std::string& arg_name="")
        const;

    // Convert HTML form data to post.
    mw::E<Post> formToPost(const httplib::Request& req, std::string_view author)
        const;

    void setup();
    nlohmann::json baseTemplateData(const httplib::Request&) const;

    const Configuration config;
    inja::Environment templates;
    std::unique_ptr<mw::AuthInterface> auth;
    std::unique_ptr<DataSourceInterface> data;
    std::unique_ptr<mw::HasherInterface> hasher;
    AttachmentManager attachment_manager;
    PostCache post_cache;
    ThemeManager theme_manager;
    mw::URL base_url;
    nlohmann::json static_template_data;
    std::atomic<bool> should_stop;
    std::thread server_thread;
    httplib::Server server;
};
