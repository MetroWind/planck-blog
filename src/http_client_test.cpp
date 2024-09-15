#include <thread>
#include <chrono>
#include <format>

#include <httplib.h>
#include <gtest/gtest.h>
#include <curl/curl.h>

#include "error.hpp"
#include "http_client.hpp"

class CurlEnv : public ::testing::Environment
{
public:
    ~CurlEnv() override = default;
    void SetUp() override
    {
        curl_global_init(CURL_GLOBAL_ALL);
    }
};

testing::Environment* const curl_env =
    testing::AddGlobalTestEnvironment(new CurlEnv);

TEST(DISABLED_HTTPSession, CanGet)
{
    using namespace std::chrono_literals;

    httplib::Server server;
    server.Get("/", [](const httplib::Request &, httplib::Response &res) {
        res.set_content("aaa", "text/plain");
    });
    int port;
    std::thread t([&]()
    {
        port = server.bind_to_any_port("localhost");
        server.listen_after_bind();
    });
    server.wait_until_ready();

    HTTPSession s;
    auto result = s.get(std::format("http://localhost:{}/", port));
    ASSERT_TRUE(result.has_value());
    const std::vector<std::byte>& payload = (*result)->payload;
    EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(payload.data()),
                               payload.size()),
              "aaa");
    EXPECT_EQ((*result)->status, 200);
    ASSERT_TRUE((*result)->header.contains("Content-Type"));
    EXPECT_EQ((*result)->header.at("Content-Type"), "text/plain");

    // HTTP error
    result = s.get(std::format("http://localhost:{}/aaa", port));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ((*result)->status, 404);

    // cURL error
    result = s.get("http://bad.invalid/");
    EXPECT_FALSE(result.has_value());

    server.stop();
    t.join();
}

TEST(DISABLED_HTTPSession, CanPost)
{
    using namespace std::chrono_literals;

    httplib::Server server;
    server.Post("/", [](const httplib::Request& req, httplib::Response& res) {
        EXPECT_FALSE(req.is_multipart_form_data());
        auto idx = req.headers.find("Content-Type");
        if(req.body == "aaa" && idx != std::end(req.headers) &&
           idx->second == "text/plain")
        {
            res.set_content("bbb", "text/plain");
        }
        else
        {
            res.set_content("error", "text/plain");
            res.status = 401;
        }
    });
    int port;
    std::thread t([&]()
    {
        port = server.bind_to_any_port("localhost");
        server.listen_after_bind();
    });
    server.wait_until_ready();

    HTTPSession s;
    {
        E<const HTTPResponse*> result = s.post(
            HTTPRequest(std::format("http://localhost:{}/", port))
            .setPayload("aaa")
            .setContentType("text/plain"));
        ASSERT_TRUE(result.has_value());
        const HTTPResponse& res = **result;
        EXPECT_EQ(res.status, 200);
        ASSERT_TRUE(res.header.contains("Content-Type"));
        EXPECT_EQ(res.header.at("Content-Type"), "text/plain");
        EXPECT_EQ(std::string_view(
                      reinterpret_cast<const char*>(res.payload.data()),
                      res.payload.size()),
                  "bbb");
    }
    {
        E<const HTTPResponse*> result = s.post(
            HTTPRequest(std::format("http://localhost:{}/", port))
            .addHeader("Content-Type", "text/plain").setPayload("nonono"));
        ASSERT_TRUE(result.has_value());
        const HTTPResponse& res = **result;
        EXPECT_EQ(res.status, 401);
        ASSERT_TRUE(res.header.contains("Content-Type"));
        EXPECT_EQ(res.header.at("Content-Type"), "text/plain");
        EXPECT_EQ(std::string_view(
                      reinterpret_cast<const char*>(res.payload.data()),
                      res.payload.size()),
                  "error");
    }


    server.stop();
    t.join();
}
