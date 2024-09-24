#include <cstddef>
#include <span>
#include <string>

#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include "hash.hpp"
#include "utils.hpp"

std::string Sha256HalfHasher::hashToHexStr(const std::string& bytes) const
{
    std::string digest;
    CryptoPP::SHA256 hash;

    CryptoPP::StringSource _(
        bytes, true, new CryptoPP::HashFilter(
            hash, new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));
    digest.resize(32);
    return toLower(digest);
}
