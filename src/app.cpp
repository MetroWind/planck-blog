#define CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH 131072

#include <algorithm>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <memory>
#include <regex>
#include <sstream>
#include <sstream>
#include <string>
#include <thread>
#include <variant>
#include <vector>

#include <inja.hpp>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "app.hpp"
#include "attachment.hpp"
#include "auth.hpp"
#include "config.hpp"
#include "error.hpp"
#include "hash.hpp"
#include "http_client.hpp"
#include "post.hpp"
#include "theme.hpp"
#include "url.hpp"
#include "utils.hpp"

#define _ASSIGN_OR_RESPOND_ERROR(tmp, var, val, res)                    \
    auto tmp = val;                                                     \
    if(!tmp.has_value())                                                \
    {                                                                   \
        if(std::holds_alternative<HTTPError>(tmp.error()))              \
        {                                                               \
            const HTTPError& e = std::get<HTTPError>(tmp.error());      \
            res.status = e.code;                                        \
            res.set_content(e.msg, "text/plain");                       \
            return;                                                     \
        }                                                               \
        else                                                            \
        {                                                               \
            res.status = 500;                                           \
            res.set_content(std::visit([](const auto& e) { return e.msg; }, \
                                       tmp.error()),                    \
                            "text/plain");                              \
            return;                                                     \
        }                                                               \
    }                                                                   \
    var = std::move(tmp).value()

// Val should be a rvalue.
#define ASSIGN_OR_RESPOND_ERROR(var, val, res)                          \
    _ASSIGN_OR_RESPOND_ERROR(_CONCAT_NAMES(assign_or_return_tmp, __COUNTER__), \
                            var, val, res)

namespace fs = std::filesystem;

namespace {
std::unordered_map<std::string, std::string> parseCookies(std::string_view value)
{
    std::unordered_map<std::string, std::string> cookies;
    size_t begin = 0;
    while(true)
    {
        if(begin >= value.size())
        {
            break;
        }

        size_t semicolon = value.find(';', begin);
        if(semicolon == std::string::npos)
        {
            semicolon = value.size();
        }

        std::string_view section = value.substr(begin, semicolon - begin);

        begin = semicolon + 1;
        // Skip spaces
        while(begin < value.size() && value[begin] == ' ')
        {
            begin++;
        }

        size_t equal = section.find('=');
        if(equal == std::string::npos) continue;
        cookies.emplace(section.substr(0, equal),
                        section.substr(equal+1, semicolon - equal - 1));
        if(semicolon >= value.size())
        {
            continue;
        }
    }
    return cookies;
}

void setTokenCookies(const Tokens& tokens, httplib::Response& res)
{
    int64_t expire_sec = 300;
    if(tokens.expiration.has_value())
    {
        auto expire = std::chrono::duration_cast<std::chrono::seconds>(
            *tokens.expiration - Clock::now());
        expire_sec = expire.count();
    }
    res.set_header("Set-Cookie", std::format(
                       "planck-blog-access-token={}; Max-Age={}",
                       urlEncode(tokens.access_token), expire_sec));
    // Add refresh token to cookie, with one month expiration.
    if(tokens.refresh_token.has_value())
    {
        expire_sec = 1800;
        if(tokens.refresh_expiration.has_value())
        {
            auto expire = std::chrono::duration_cast<std::chrono::seconds>(
                *tokens.refresh_expiration - Clock::now());
            expire_sec = expire.count();
        }

        res.set_header("Set-Cookie", std::format(
                           "planck-blog-refresh-token={}; Max-Age={}",
                           urlEncode(*tokens.refresh_token), expire_sec));
    }
}

E<nlohmann::json> postExcerptToJson(const Post& p)
{
    if(!p.id.has_value())
    {
        return std::unexpected(runtimeError(
            "Only post with an ID can be listed"));
    }

    nlohmann::json result;
    result["id"] = std::to_string(*p.id);
    result["title"] = p.title;
    result["abstract"] = p.abstract;
    result["language"] = p.language;

    return result;
}

} // namespace

void copyToHttplibReq(const HTTPRequest& src, httplib::Request& dest)
{
    std::string type = "text/plain";
    if(auto it = src.header.find("Content-Type");
       it != std::end(src.header))
    {
        type = src.header.at("Content-Type");
    }
    dest.set_header("Content-Type", type);
    dest.body = src.request_data;
    for(const auto& [key, value]: src.header)
    {
        if(key != "Content-Type")
        {
            dest.set_header(key, value);
        }
    }
}

E<App::SessionValidation> App::validateSession(const httplib::Request& req) const
{
    if(!req.has_header("Cookie"))
    {
        spdlog::debug("Request has no cookie.");
        return SessionValidation::invalid();
    }

    auto cookies = parseCookies(req.get_header_value("Cookie"));
    if(auto it = cookies.find("planck-blog-access-token");
       it != std::end(cookies))
    {
        spdlog::debug("Cookie has access token.");
        Tokens tokens;
        tokens.access_token = it->second;
        E<UserInfo> user = auth->getUser(tokens);
        if(user.has_value())
        {
            return SessionValidation::valid(*std::move(user));
        }
    }
    // No access token or access token expired
    if(auto it = cookies.find("planck-blog-refresh-token");
       it != std::end(cookies))
    {
        spdlog::debug("Cookie has refresh token.");
        // Try to refresh the tokens.
        ASSIGN_OR_RETURN(Tokens tokens, auth->refreshTokens(it->second));
        ASSIGN_OR_RETURN(UserInfo user, auth->getUser(tokens));
        return SessionValidation::refreshed(std::move(user), std::move(tokens));
    }
    return SessionValidation::invalid();
}

std::optional<App::SessionValidation> App::prepareSession(
    const httplib::Request& req, httplib::Response& res,
    bool allow_error_and_invalid) const
{
    E<SessionValidation> session = validateSession(req);
    if(!session.has_value())
    {
        if(allow_error_and_invalid)
        {
            return SessionValidation::invalid();
        }
        else
        {
            res.status = 500;
            res.set_content("Failed to validate session.", "text/plain");
            return std::nullopt;
        }
    }

    switch(session->status)
    {
    case SessionValidation::INVALID:
        if(allow_error_and_invalid)
        {
            return *session;
        }
        else
        {
            res.status = 401;
            res.set_content("Invalid session.", "text/plain");
            break;
        }
    case SessionValidation::VALID:
        break;
    case SessionValidation::REFRESHED:
        setTokenCookies(session->new_tokens, res);
        break;
    }
    return *session;
}

App::App(const Configuration& conf, std::unique_ptr<AuthInterface> openid_auth,
         std::unique_ptr<DataSourceInterface> data_source)
        : config(conf),
          templates((std::filesystem::path(config.data_dir) / "templates" / "")
                    .string()),
          auth(std::move(openid_auth)),
          data(std::move(data_source)),
          hasher(std::make_unique<Sha256HalfHasher>()),
          attachment_manager(*hasher),
          post_cache(conf),
          theme_manager(),
          base_url(),
          should_stop(false)
{
    auto u = URL::fromStr(conf.base_url);
    if(u.has_value())
    {
        base_url = *std::move(u);
    }

    templates.add_callback("url_for", [&](const inja::Arguments& args) ->
                           std::string
    {
        switch(args.size())
        {
        case 1:
            return urlFor(args.at(0)->get_ref<const std::string&>());
        case 2:
            return urlFor(args.at(0)->get_ref<const std::string&>(),
                          args.at(1)->get_ref<const std::string&>());
        default:
            return "Invalid number of url_for() arguments";
        }
    });

    if(E<void> result = theme_manager.loadDir(
           fs::path(config.data_dir) / "themes");
       !result)
    {
        spdlog::error("Failed to load themes: {}", errorMsg(result.error()));
    }

    static_template_data = {{"blog_title", config.blog_title},
                            {"themes", theme_manager.themeNames()}};
    setup();
}

std::string App::urlFor(const std::string& name, const std::string& arg) const
{
    if(name == "index")
    {
        return base_url.str();
    }
    if(name == "openid-redirect")
    {
        return URL(base_url).appendPath("openid-redirect").str();
    }
    if(name == "statics")
    {
        return URL(base_url).appendPath("statics").appendPath(arg).str();
    }
    if(name == "stylesheet")
    {
        return URL(base_url).appendPath("themes").appendPath(arg).str();
    }
    if(name == "login")
    {
        return URL(base_url).appendPath("login").str();
    }
    if(name == "post")
    {
        return URL(base_url).appendPath("p").appendPath(arg).str();
    }
    if(name == "drafts")
    {
        return URL(base_url).appendPath("drafts").str();
    }
    if(name == "attachment")
    {
        if(arg.contains('/'))
        {
            return URL(base_url).appendPath("attachment").appendPath(arg).str();
        }
        else
        {
            auto att_maybe = data->getAttachment(arg);
            if(att_maybe.has_value())
            {
                if(att_maybe->has_value())
                {
                    return URL(base_url).appendPath("attachment")
                        .appendPath(arg).appendPath((*att_maybe)->original_name)
                        .str();
                }
            }
        }
        return "";
    }
    if(name == "attachments")
    {
        return URL(base_url).appendPath("attachments").str();
    }
    if(name == "create-post")
    {
        return URL(base_url).appendPath("create-post").str();
    }
    if(name == "edit-post")
    {
        return URL(base_url).appendPath("edit-post").appendPath(arg).str();
    }
    if(name == "edit-draft")
    {
        return URL(base_url).appendPath("edit-draft").appendPath(arg).str();
    }
    // POST endpoints
    if(name == "save-draft")
    {
        return URL(base_url).appendPath("save-draft").str();
    }
    if(name == "save-post")
    {
        return URL(base_url).appendPath("save-post").str();
    }
    if(name == "publish-from-draft")
    {
        return URL(base_url).appendPath("publish-from-new-draft").str();
    }
    if(name == "upload-attachment")
    {
        return URL(base_url).appendPath("upload-attachment").str();
    }
    if(name == "select-theme")
    {
        return URL(base_url).appendPath("select-theme").str();
    }
    if(name == "feed")
    {
        return URL(base_url).appendPath("feed.xml").str();
    }
    return "";
}

void App::handleIndex(const httplib::Request& req, httplib::Response& res)
{
    auto session = prepareSession(req, res, true);

    ASSIGN_OR_RESPOND_ERROR(std::vector<Post> posts, data->getPostExcerpts(), res);
    nlohmann::json posts_json = nlohmann::json::array();
    for(const Post& p: posts)
    {
        ASSIGN_OR_RESPOND_ERROR(nlohmann::json pj, postExcerptToJson(p), res);
        posts_json.push_back(std::move(pj));
    }
    nlohmann::json data = baseTemplateData(req);
    data.merge_patch({{"posts", std::move(posts_json)},
                      {"session_user", session->user.name}});
    std::string result = templates.render_file(
        "index.html", std::move(data));
    res.status = 200;
    res.set_content(result, "text/html");
}

void App::handleLogin(httplib::Response& res) const
{
    res.set_redirect(auth->initialURL(), 301);
}

void App::handleOpenIDRedirect(const httplib::Request& req,
                               httplib::Response& res) const
{
    if(req.has_param("error"))
    {
        res.status = 500;
        if(req.has_param("error_description"))
        {
            res.set_content(
                std::format("{}: {}.", req.get_param_value("error"),
                            req.get_param_value("error_description")),
                "text/plain");
        }
        return;
    }
    else if(!req.has_param("code"))
    {
        res.status = 500;
        res.set_content("No error or code in auth response", "text/plain");
        return;
    }

    std::string code = req.get_param_value("code");
    spdlog::debug("OpenID server visited {} with code {}.", req.path, code);
    ASSIGN_OR_RESPOND_ERROR(Tokens tokens, auth->authenticate(code), res);
    ASSIGN_OR_RESPOND_ERROR(UserInfo user, auth->getUser(tokens), res);

    setTokenCookies(tokens, res);
    res.set_redirect(urlFor("index"), 301);
}

void App::handlePost(const httplib::Request& req, httplib::Response& res)
{
    ASSIGN_OR_RESPOND_ERROR(
        int64_t id, strToNumber<int64_t>(req.path_params.at("id")).or_else(
            []([[maybe_unused]] auto _) -> E<int64_t>
            {
                return std::unexpected(httpError(401, "Invalid post ID"));
            }), res);

    auto session = prepareSession(req, res, true);

    ASSIGN_OR_RESPOND_ERROR(std::optional<Post> p, data->getPost(id), res);
    if(!p.has_value())
    {
        res.status = 404;
        res.set_content("Post not found", "text/plain");
        return;
    }

    ASSIGN_OR_RESPOND_ERROR(nlohmann::json pj, renderPostToJson(*std::move(p)), res);
    nlohmann::json data = baseTemplateData(req);
    data.merge_patch({{"post", std::move(pj)},
                      {"session_user", session->user.name}});
    std::string result = templates.render_file(
        "post.html", std::move(data));
    res.status = 200;
    res.set_content(std::move(result), "text/html");
}

void App::handleDrafts(const httplib::Request& req, httplib::Response& res)
{
    auto session = prepareSession(req, res);
    if(!session) return;

    ASSIGN_OR_RESPOND_ERROR(std::vector<Post> drafts, data->getDrafts(), res);
    nlohmann::json drafts_json = nlohmann::json::array();
    for(const Post& d: drafts)
    {
        ASSIGN_OR_RESPOND_ERROR(auto dj, postExcerptToJson(d), res);
        drafts_json.push_back(std::move(dj));
    }
    nlohmann::json data = baseTemplateData(req);
    data.merge_patch({{"drafts", std::move(drafts_json)},
                      {"session_user", session->user.name}});

    std::string result = templates.render_file(
        "drafts.html", std::move(data));
    res.status = 200;
    res.set_content(result, "text/html");
}

void App::handleCreatePostFrontEnd(const httplib::Request& req,
                                   httplib::Response& res)
{
    auto session = prepareSession(req, res);
    if(!session.has_value()) return;

    nlohmann::json data = baseTemplateData(req);
    data.merge_patch({{"languages", config.languages},
                      {"session_user", session->user.name}});
    std::string result = templates.render_file(
        "create_post.html", std::move(data));
    res.status = 200;
    res.set_content(result, "text/html");
}

void App::handleSaveDraft(const httplib::Request& req,
                            httplib::Response& res) const
{
    auto session = prepareSession(req, res);
    if(!session.has_value()) return;

    ASSIGN_OR_RESPOND_ERROR(Post draft, formToPost(req, session->user.name), res);
    int64_t id;
    if(draft.id.has_value())
    {
        id = *draft.id;
        auto ok_maybe = data->editDraft(draft);
        if(!ok_maybe)
        {
            res.status = 500;
            res.set_content(errorMsg(ok_maybe.error()), "text/plain");
            return;
        }
    }
    else
    {
        ASSIGN_OR_RESPOND_ERROR(id, data->saveDraft(std::move(draft)),
                                res);
    }
    res.set_redirect(urlFor("edit-draft", std::to_string(id)));
}
void App::handleEditDraftFrontEnd(const httplib::Request& req,
                                  httplib::Response& res)
{
    ASSIGN_OR_RESPOND_ERROR(
        int64_t id, strToNumber<int64_t>(req.path_params.at("id")).or_else(
            []([[maybe_unused]] auto _) -> E<int64_t>
            {
                return std::unexpected(httpError(401, "Invalid post ID"));
            }), res);

    auto session = prepareSession(req, res);
    if(!session.has_value()) return;

    ASSIGN_OR_RESPOND_ERROR(std::optional<Post> p, data->getDraft(id), res);
    if(!p.has_value())
    {
        res.status = 404;
        res.set_content("Draft not found", "text/plain");
        return;
    }

    nlohmann::json data = baseTemplateData(req);
    data.merge_patch({{"languages", config.languages},
                      {"session_user", session->user.name},
                      {"post", postToJson(*p)}});
    std::string result = templates.render_file(
        "edit_draft.html", std::move(data));
    res.status = 200;
    res.set_content(result, "text/html");
}

void App::handleEditPostFrontEnd(const httplib::Request& req,
                                 httplib::Response& res)
{
    ASSIGN_OR_RESPOND_ERROR(
        int64_t id, strToNumber<int64_t>(req.path_params.at("id")).or_else(
            []([[maybe_unused]] auto _) -> E<int64_t>
            {
                return std::unexpected(httpError(401, "Invalid post ID"));
            }), res);

    auto session = prepareSession(req, res);
    if(!session.has_value()) return;

    ASSIGN_OR_RESPOND_ERROR(std::optional<Post> p, data->getPost(id), res);
    if(!p.has_value())
    {
        res.status = 404;
        res.set_content("Post not found", "text/plain");
        return;
    }

    nlohmann::json data = baseTemplateData(req);
    data.merge_patch({{"languages", config.languages},
                      {"session_user", session->user.name},
                      {"post", postToJson(*p)}});
    std::string result = templates.render_file(
        "edit_post.html", std::move(data));
    res.status = 200;
    res.set_content(result, "text/html");
}

void App::handleSavePost(const httplib::Request& req, httplib::Response& res)
    const
{
    auto session = prepareSession(req, res);
    if(!session.has_value()) return;

    ASSIGN_OR_RESPOND_ERROR(Post p, formToPost(req, session->user.name), res);
    if(!p.id.has_value())
    {
        res.status = 400;
        res.set_content("Post should have an ID.", "text/plain");
        return;
    }

    E<nlohmann::json> value = data->getValueWithDefault(
        "pause-update-time", false);
    if(!value.has_value())
    {
        res.status = 500;
        res.set_content(errorMsg(value.error()), "text/plain");
        return;
    }
    E<void> maybe_error;
    if(value->get<bool>())
    {
        maybe_error = data->updatePostNoUpdateTime(p);
    }
    else
    {
        maybe_error = data->updatePost(std::move(p));
    }

    if(!maybe_error.has_value())
    {
        res.status = 500;
        res.set_content(std::string("Failed to save post: ") +
                        errorMsg(maybe_error.error()), "text/plain");
        return;
    }
    res.set_redirect(urlFor("post", std::to_string(*p.id)));
}

void App::handlePublishFromDraft(const httplib::Request& req, httplib::Response& res)
    const
{
    auto session = prepareSession(req, res);
    if(!session.has_value()) return;

    ASSIGN_OR_RESPOND_ERROR(Post draft, formToPost(req, session->user.name),
                            res);
    int64_t id;
    if(draft.id.has_value())
    {
        id = *draft.id;
        auto ok_maybe = data->editDraft(draft);
        if(!ok_maybe)
        {
            res.status = 500;
            res.set_content(errorMsg(ok_maybe.error()), "text/plain");
            return;
        }
    }
    else
    {
        ASSIGN_OR_RESPOND_ERROR(id, data->saveDraft(std::move(draft)),
                                res);
    }
    if(!data->publishPost(id))
    {
        res.status = 500;
        res.set_content("Failed to publish", "text/plain");
        return;
    }
    res.set_redirect(urlFor("post", std::to_string(id)));
}

void App::handleAttachments(const httplib::Request& req, httplib::Response& res)
{
    auto session = prepareSession(req, res);
    if(!session) return;

    ASSIGN_OR_RESPOND_ERROR(
        std::vector<Attachment> atts, data->getAttachments(), res);

    nlohmann::json atts_json = nlohmann::json::array();
    for(const Attachment& att: atts)
    {
        atts_json.push_back({
                { "original_name", att.original_name },
                { "hash", att.hash },
                { "upload_time", timeToSeconds(att.upload_time) },
                { "upload_time_str", timeToStr(att.upload_time) },
                { "upload_time_iso8601", timeToISO8601(att.upload_time) },
                { "content_type", att.content_type },
                { "url", urlFor("attachment",
                                att.hash + "/" + att.original_name) }
            });
    }

    nlohmann::json data = baseTemplateData(req);
    data.merge_patch({{"attachments", std::move(atts_json)},
                      {"session_user", session->user.name}});

    std::string result = templates.render_file(
        "attachments.html", std::move(data));
    res.status = 200;
    res.set_content(result, "text/html");
}

void App::handleAttachment(const httplib::Request& req, httplib::Response& res)
{
    ASSIGN_OR_RESPOND_ERROR(
        std::optional<Attachment> att,
        data->getAttachment(req.path_params.at("hash")),
        res);
    if(!att.has_value())
    {
        res.status = 404;
        res.set_content("Attachment not found", "text/plain");
        return;
    }

    auto path = fs::path(config.attachment_dir) / attachment_manager.path(*att);
    if(!fs::exists(path))
    {
        res.status = 404;
        res.set_content("File not found", "text/plain");
        return;
    }

    std::ifstream file(path);
    std::string data(std::istreambuf_iterator<char>{file}, {});
    file.close();
    res.status = 200;
    res.set_content(data, att->content_type);
}

void App::handleAttachmentUpload(const httplib::Request& req,
                                 httplib::Response& res) const
{
    auto session = prepareSession(req, res);
    if(!session) return;

    if(!req.has_file("file"))
    {
        res.status = 400;
        res.set_content("File expected", "text/plain");
        return;
    }
    const auto& file = req.get_file_value("file");
    Attachment att = attachment_manager.attachmentFromBytes(
        file.content, file.filename, file.content_type);
    fs::path path = fs::path(config.attachment_dir) /
        attachment_manager.path(att);
    fs::path dir = path.parent_path();
    if(!fs::exists(dir))
    {
        if(!fs::create_directory(dir))
        {
            res.status = 500;
            res.set_content("Failed to create directory for attachment",
                            "text/plain");
            return;
        }
    }
    std::ofstream att_file(path);
    try
    {
        att_file.write(file.content.data(), file.content.size());
    }
    catch(const std::ios_base::failure& e)
    {
        res.status = 500;
        res.set_content(std::format("Failed to write attachment: {}", e.what()),
                        "text/plain");
        return;
    }
    att_file.close();
    E<void> error_maybe = data->addAttachment(std::move(att));
    if(!error_maybe)
    {
        fs::remove(path);
        res.status = 500;
        res.set_content(errorMsg(error_maybe.error()), "text/plain");
        return;
    }
    res.set_redirect(urlFor("attachments"));
}

void App::handleSelectTheme(const httplib::Request& req, httplib::Response& res)
    const
{
    nlohmann::json data = parseJSON(req.body);
    if(data.is_discarded())
    {
        res.status = 400;
        res.set_content("Select theme request should be JSON", "text/plain");
        return;
    }

    const auto& theme_obj = data["theme"];
    if(!theme_obj.is_string())
    {
        res.status = 400;
        res.set_content("Invalid select theme request", "text/plain");
        return;
    }
    std::string_view theme = theme_obj.get_ref<const std::string&>();
    res.set_header("Set-Cookie", std::format(
        "planck-blog-theme={}; Max-Age=315360000", theme));
    res.status = 204;
}

void App::handleFeed(const httplib::Request& req, httplib::Response& res)
{
    ASSIGN_OR_RESPOND_ERROR(std::vector<Post> ps, data->getPosts(0, 5), res);
    nlohmann::json posts_json = nlohmann::json::array();
    for(Post& p: ps)
    {
        ASSIGN_OR_RESPOND_ERROR(nlohmann::json pj,
                                renderPostToJson(std::move(p)), res);
        pj["content"] = escapeHTML(pj["content"].get_ref<std::string&>());
        posts_json.push_back(std::move(pj));
    }
    ASSIGN_OR_RESPOND_ERROR(Time latest_update, data->getLatestUpdateTime(),
                            res);
    nlohmann::json data = baseTemplateData(req);
    data.merge_patch({{"posts", std::move(posts_json)},
                      {"latest_update_time", timeToISO8601(latest_update)}});
    std::string result = templates.render_file(
        "feed.xml", std::move(data));
    res.status = 200;
    res.set_content(std::move(result), "application/atom+xml");
}

nlohmann::json App::postToJson(const Post& p) const
{
    nlohmann::json result;
    if(p.id.has_value())
    {
        result["id"] = std::to_string(*p.id);
    }
    result["markup"] = Post::markupToStr(p.markup);
    result["title"] = p.title;
    result["abstract"] = p.abstract;
    result["content"] = p.raw_content;
    const Time APOCH = secondsToTime(0);
    Time publish_time = APOCH;
    if(p.publish_time.has_value())
    {
        publish_time = *p.publish_time;
        result["publish_time"] = timeToSeconds(publish_time);
        result["publish_time_str"] = timeToStr(*p.publish_time);
        result["publish_time_iso8601"] = timeToISO8601(*p.publish_time);
    }
    else
    {
        result["publish_time"] = 0;
        result["publish_time_str"] = "";
        result["publish_time_iso8601"] = "";
    }

    Time update_time = APOCH;
    if(p.update_time.has_value())
    {
        update_time = *p.update_time;
        result["update_time"] = timeToSeconds(update_time);
        result["update_time_str"] = timeToStr(*p.update_time);
        result["update_time_iso8601"] = timeToISO8601(*p.update_time);
    }
    else
    {
        result["update_time"] = 0;
        result["update_time_str"] = "";
        result["update_time_iso8601"] = "";
    }

    const Time& change_time = std::max(update_time, publish_time);
    if(change_time > APOCH)
    {
        result["change_time"] = timeToSeconds(change_time);
        result["change_time_str"] = timeToStr(change_time);
        result["change_time_iso8601"] = timeToISO8601(change_time);
    }
    else
    {
        result["change_time"] = 0;
        result["change_time_str"] = "";
        result["change_time_iso8601"] = "";
    }

    result["language"] = p.language;
    result["author"] = p.author;

    return result;
}

E<nlohmann::json> App::renderPostToJson(Post&& p)
{
    nlohmann::json result = postToJson(p);
    // Do template substitution in the post content. This allows
    // writer to write {{ url_for(...) }} in the post. If this fails,
    // we’ll just use the post content as-is.
    nlohmann::json data;
    try
    {
        p.raw_content = templates.render(p.raw_content, std::move(data));
    }
    catch(const inja::InjaError& e)
    {
        spdlog::warn(
            "Failed to do template substitution on the post content: {}",
            e.message);
    }
    ASSIGN_OR_RETURN(result["content"], post_cache.renderPost(p));
    return result;
}

std::string App::getPath(const std::string& name,
                         const std::string& arg_name) const
{
    return URL::fromStr(urlFor(name, std::string(":") + arg_name)).value()
        .path();
}

E<Post> App::formToPost(const httplib::Request& req, std::string_view author) const
{
    Post draft;
    if(auto m = Post::markupFromStr(req.get_param_value("markup"));
       m.has_value())
    {
        draft.markup = *m;
    }
    else
    {
        return std::unexpected(httpError(400, "Invalid markup"));
    }
    if(req.has_param("id"))
    {
        ASSIGN_OR_RETURN(
            draft.id, strToNumber<int64_t>(req.get_param_value("id")));
    }
    draft.title = req.get_param_value("title");
    draft.abstract = strip(req.get_param_value("abstract"));
    draft.raw_content = strip(req.get_param_value("content"));
    draft.language = req.get_param_value("language");
    draft.author = author;
    return draft;
}

void App::setup()
{
    {
        std::string statics_dir = (std::filesystem::path(config.data_dir) /
                                   "statics").string();
        spdlog::info("Mounting static dir at {}...", statics_dir);
        auto ret = server.set_mount_point(
            URL(base_url).appendPath("statics").path(), statics_dir);
        if (!ret)
        {
            spdlog::error("Failed to mount statics");
            return;
        }
    }
    {
        std::string themes_dir = (std::filesystem::path(config.data_dir) /
                                 "themes").string();
        spdlog::info("Mounting themes dir at {}...", themes_dir);
        auto ret = server.set_mount_point(
            URL(base_url).appendPath("themes").path(), themes_dir);
        if (!ret)
        {
            spdlog::error("Failed to mount themes");
            return;
        }
    }

    server.Get(getPath("index"), [&](const httplib::Request& req,
                                     httplib::Response& res)
    {
        handleIndex(req, res);
    });
    server.Get(getPath("login"), [&]([[maybe_unused]] const httplib::Request& req,
                                     httplib::Response& res)
    {
        handleLogin(res);
    });
    server.Get(getPath("openid-redirect"),
               [&](const httplib::Request& req, httplib::Response& res)
    {
        handleOpenIDRedirect(req, res);
    });
    server.Get(getPath("post", "id"), [&](const httplib::Request& req,
                                          httplib::Response& res)
    {
        handlePost(req, res);
    });
    server.Get(getPath("drafts"), [&](const httplib::Request& req,
                                      httplib::Response& res)
    {
        handleDrafts(req, res);
    });
    server.Get(getPath("create-post"),
               [&](const httplib::Request& req, httplib::Response& res)
    {
        handleCreatePostFrontEnd(req, res);
    });
    server.Get(getPath("edit-draft", "id"),
               [&](const httplib::Request& req, httplib::Response& res)
    {
        handleEditDraftFrontEnd(req, res);
    });
    server.Get(getPath("edit-post", "id"),
               [&](const httplib::Request& req, httplib::Response& res)
    {
        handleEditPostFrontEnd(req, res);
    });
    server.Post(getPath("save-post"),
                [&](const httplib::Request& req, httplib::Response& res)
    {
        handleSavePost(req, res);
    });
    server.Post(getPath("save-draft"),
                [&](const httplib::Request& req, httplib::Response& res)
    {
        handleSaveDraft(req, res);
    });
    server.Post(getPath("publish-from-draft"),
                [&](const httplib::Request& req, httplib::Response& res)
    {
        handlePublishFromDraft(req, res);
    });
    server.Get(getPath("attachments"),
                [&](const httplib::Request& req, httplib::Response& res)
    {
        handleAttachments(req, res);
    });
    server.Get(getPath("attachment", "hash/:_"),
                [&](const httplib::Request& req, httplib::Response& res)
    {
        handleAttachment(req, res);
    });
    server.Post(getPath("upload-attachment"),
                [&](const httplib::Request& req, httplib::Response& res)
    {
        handleAttachmentUpload(req, res);
    });
    server.Post(getPath("select-theme"),
                [&](const httplib::Request& req, httplib::Response& res)
    {
        handleSelectTheme(req, res);
    });
    server.Get(getPath("feed"),
                [&](const httplib::Request& req, httplib::Response& res)
    {
        handleFeed(req, res);
    });
}

nlohmann::json App::baseTemplateData(const httplib::Request& req) const
{
    nlohmann::json data = static_template_data;
    data["stylesheets"] = nlohmann::json::array();
    std::string theme = config.default_theme;
    auto cookies = parseCookies(req.get_header_value("Cookie"));
    if(auto it = cookies.find("planck-blog-theme");
       it != std::end(cookies))
    {
        theme = it->second;
    }
    data["stylesheets"] = theme_manager.stylesheets(theme);
    data["current_theme"] = theme;
    data["nav_center"] = config.substitutions.nav_center;
    data["after_post"] = config.substitutions.after_post;
    return data;
}

void App::start()
{
    spdlog::info("Listening at http://{}:{}/...", config.listen_address,
                 config.listen_port);
    server_thread = std::thread([&] {
        try
        {
            server.listen(config.listen_address, config.listen_port);
        }
        catch(...)
        {
            spdlog::error("Exception when listing.");
        }
    });
    while(!server.is_running());
    server.wait_until_ready();
}

void App::stop()
{
    should_stop = true;
    server.stop();
}

void App::wait()
{
    while(!should_stop && server.is_running());
    server_thread.join();
}
