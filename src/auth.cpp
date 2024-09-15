#include <chrono>
#include <memory>
#include <expected>
#include <string>
#include <string_view>
#include <format>

#include <nlohmann/json.hpp>

#include "auth.hpp"
#include "config.hpp"
#include "error.hpp"
#include "http_client.hpp"
#include "utils.hpp"
#include "spdlog/spdlog.h"

E<std::string> getStrProperty(
    const nlohmann::json& json_dict, std::string_view property)
{
    if(json_dict.contains(property) && json_dict[property].is_string())
    {
        return json_dict[property].get<std::string>();
    }
    else
    {
        return std::unexpected(runtimeError(std::format("Invalid value of {}", property)));
    }
}

E<int> getIntProperty(
    const nlohmann::json& json_dict, std::string_view property)
{
    if(json_dict.contains(property) && json_dict[property].is_number_integer())
    {
        return json_dict[property].get<int>();
    }
    else
    {
        return std::unexpected(runtimeError(std::format("Invalid value of {}", property)));
    }
}

E<Tokens> tokensFromResponse(const HTTPResponse& res)
{
    nlohmann::json data = parseJSON(res.payloadAsStr());
    if(data.is_discarded())
    {
        return std::unexpected(runtimeError("Invalid token response"));
    }
    if(res.status != 200)
    {
        auto err = getStrProperty(data, "error_description");
        std::string_view msg;
        if(err.has_value())
        {
            msg = *err;
        }
        return std::unexpected(httpError(res.status, msg));
    }

    Tokens tokens;
    ASSIGN_OR_RETURN(tokens.access_token, getStrProperty(data, "access_token"));
    if(auto refresh_token = getStrProperty(data, "refresh_token");
       refresh_token.has_value())
    {
        tokens.refresh_token = *std::move(refresh_token);
    }
    if(auto seconds = getIntProperty(data, "expires_in");
       seconds.has_value())
    {
        tokens.expiration = Clock::now() + std::chrono::seconds(*seconds);
    }
    if(auto seconds = getIntProperty(data, "refresh_expires_in");
       seconds.has_value())
    {
        tokens.refresh_expiration = Clock::now() +
            std::chrono::seconds(*seconds);
    }
    return tokens;
}

E<std::unique_ptr<AuthOpenIDConnect>> AuthOpenIDConnect::create(
    const Configuration& config, std::string_view redirect_url,
    std::unique_ptr<HTTPSessionInterface> http)
{
    std::string prefix = config.openid_url_prefix;
    if(http == nullptr)
    {
        return std::unexpected(runtimeError("Null HTTP client"));
    }
    if(prefix.empty())
    {
        return std::unexpected(runtimeError("Empty auth prefix"));
    }

    // TODO: use the URL class to process the prefix.
    //
    // Remove trailing slashes from URL prefix.
    while(prefix.back() == '/')
    {
        prefix.pop_back();
        if(prefix.empty())
        {
            return std::unexpected(runtimeError("Invalid auth prefix"));
        }
    }

    std::string url = std::move(prefix) + "/.well-known/openid-configuration";
    E<const HTTPResponse*> result = http->get(url);
    if(!result.has_value())
    {
        return std::unexpected(result.error());
    }

    const HTTPResponse& res = **result;
    nlohmann::json data = parseJSON(res.payload);
    if(data.is_discarded())
    {
        return std::unexpected(
            runtimeError("Invalid OpenID configuration from server"));
    }
    auto auth = std::make_unique<AuthOpenIDConnect>(
        config, redirect_url, std::move(http));

    ASSIGN_OR_RETURN(auth->endpoint_auth,
                     getStrProperty(data, "authorization_endpoint"));
    ASSIGN_OR_RETURN(auth->endpoint_token,
                     getStrProperty(data, "token_endpoint"));
    ASSIGN_OR_RETURN(auth->endpoint_introspect,
                     getStrProperty(data, "introspection_endpoint"));
    ASSIGN_OR_RETURN(auth->endpoint_user_info,
                     getStrProperty(data, "userinfo_endpoint"));
    return auth;
}

std::string AuthOpenIDConnect::initialURL() const
{
    return std::format(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile",
        endpoint_auth, urlEncode(config.client_id), urlEncode(redirection_url));
}

E<HTTPResponse> AuthOpenIDConnect::initiate() const
{
    E<const HTTPResponse*> res = http_client->get(initialURL());
    return res.transform([](const auto* r) { return *r; });
}

E<Tokens> AuthOpenIDConnect::authenticate(std::string_view code) const
{
    // TODO: support client with public access type (no client
    // secret).
    std::string payload = std::format(
        "grant_type=authorization_code&code={}&redirect_uri={}"
        "&client_id={}&client_secret={}",
        urlEncode(code), urlEncode(redirection_url),
        urlEncode(config.client_id), urlEncode(config.client_secret));
    ASSIGN_OR_RETURN(const HTTPResponse* res, http_client->post(
        HTTPRequest(endpoint_token).setPayload(payload)
        .addHeader("Content-Type", "application/x-www-form-urlencoded")
        .addHeader("Authorization", std::string("Basic ") +
                   urlEncode(config.client_secret))));

    if(res->status != 200)
    {
        return std::unexpected(
            httpError(res->status, res->payloadAsStr()));
    }
    return tokensFromResponse(*res);
}

E<UserInfo> AuthOpenIDConnect::getUser(const Tokens& tokens) const
{
    ASSIGN_OR_RETURN(const HTTPResponse* res, http_client->get(
        HTTPRequest(endpoint_user_info).addHeader(
            "Authorization", std::string("Bearer ") +
            urlEncode(tokens.access_token))));

    nlohmann::json data = parseJSON(res->payloadAsStr());
    if(data.is_discarded())
    {
        return std::unexpected(runtimeError("Invalid user info response"));
    }

    UserInfo user;
    ASSIGN_OR_RETURN(user.id, getStrProperty(data, "sub"));
    if(data.contains("name"))
    {
        ASSIGN_OR_RETURN(user.name, getStrProperty(data, "name"));
    }
    else if(data.contains("preferred_username"))
    {
        ASSIGN_OR_RETURN(user.name, getStrProperty(data, "preferred_username"));
    }
    return user;
}

E<Tokens> AuthOpenIDConnect::refreshTokens(std::string_view refresh_token) const
{
    std::string token_payload = std::format(
        "client_id={}"
        "&client_secret={}"
        "&grant_type=refresh_token"
        "&refresh_token={}"
        "&scope=openid%20profile",
        urlEncode(config.client_id), urlEncode(config.client_secret),
        urlEncode(refresh_token));
    ASSIGN_OR_RETURN(const HTTPResponse* res, http_client->post(
        HTTPRequest(endpoint_token)
        .addHeader("Authorization", std::string("Basic ") +
                   urlEncode(config.client_secret))
        .setContentType("application/x-www-form-urlencoded")
        .setPayload(std::move(token_payload))));
    return tokensFromResponse(*res);
}
