#pragma once

#include <string>

#include <gmock/gmock.h>

#include "hash.hpp"

class HasherMock : public HasherInterface
{
public:
    ~HasherMock() override = default;
    MOCK_METHOD(std::string, hashToHexStr, (const std::string& bytes),
                (const override));
};
