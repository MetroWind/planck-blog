#pragma once

#include <cstddef>
#include <span>
#include <string>

class HasherInterface
{
public:
    virtual ~HasherInterface() = default;
    // Calculate the hash of the bytes, and return the hex string
    // representation of the hash in lowercase.
    virtual std::string hashToHexStr(const std::string& bytes) const = 0;
};

// This hasher takes the first half of the SHA256 hash.
class Sha256HalfHasher : public HasherInterface
{
public:
    ~Sha256HalfHasher() override = default;
    std::string hashToHexStr(const std::string& bytes) const override;
};
