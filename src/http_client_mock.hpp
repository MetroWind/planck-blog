#pragma once

#include <string>

#include <gmock/gmock.h>

#include "http_client.hpp"
#include "error.hpp"

class HTTPSessionMock : public HTTPSessionInterface
{
public:
    ~HTTPSessionMock() override = default;
    MOCK_METHOD(E<const HTTPResponse*>, get, (const HTTPRequest& req),
                (override));
    MOCK_METHOD(E<const HTTPResponse*>, post, (const HTTPRequest& req),
                (override));
};
