#pragma once

#include <string>
#include <string_view>

#include <gmock/gmock.h>

#include "http_client.hpp"
#include "auth.hpp"
#include "error.hpp"

class AuthMock : public AuthInterface
{
public:
    ~AuthMock() override = default;
    MOCK_METHOD(std::string, initialURL, (), (const override));
    MOCK_METHOD(E<HTTPResponse>, initiate, (), (const override));
    MOCK_METHOD(E<Tokens>, authenticate, (std::string_view code),
                (const override));
    MOCK_METHOD(E<UserInfo>, getUser, (const Tokens& tokens), (const override));
    MOCK_METHOD(E<Tokens>, refreshTokens, (std::string_view refresh_token),
                (const override));
};
