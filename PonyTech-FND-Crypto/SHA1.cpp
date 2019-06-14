#include <PonyTech-FND-Crypto/PonyTech-FND-Crypto.hpp>
#include "../catch.hpp"
#include "../StdStringHelper.hpp"

using namespace FND;
using namespace FND::Crypto;

TEST_CASE("Testing SHA1 - empty", "[crypto]")
{
    String output;
    SHA1 sha1;
    Array<byte_t> result;

    sha1.digest(result);
    {   ManagedStringBuffer buffer(output);
        Utf8OutputStream stream(buffer);
        stream.write(result);
    }

    REQUIRE(toStdString(output) == "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
}

TEST_CASE("Testing SHA1 - test vector ", "[crypto]")
{
    String output;
    SHA1 sha1;
    Array<byte_t> result;

    SECTION("abc")
    {
        const char *data = "abc";
        ConstArray<byte_t> content(reinterpret_cast<const uint8_t*>(data), PxConstStringHelper::length(data));
        sha1.update(content);
        sha1.digest(result);
        {   ManagedStringBuffer buffer(output);
            Utf8OutputStream stream(buffer);
            stream.write(result);
        }

        REQUIRE(toStdString(output) == "A9993E364706816ABA3E25717850C26C9CD0D89D");
    }
    SECTION("long abc")
    {
        const char *data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        ConstArray<byte_t> content(reinterpret_cast<const uint8_t*>(data), PxConstStringHelper::length(data));
        sha1.update(content);
        sha1.digest(result);
        {   ManagedStringBuffer buffer(output);
            Utf8OutputStream stream(buffer);
            stream.write(result);
        }
        REQUIRE(toStdString(output) == "84983E441C3BD26EBAAE4AA1F95129E5E54670F1");
    }  
}


TEST_CASE("Testing SHA1 - wiki", "[crypto]")
{
    String output;
    SHA1 sha1;
    Array<byte_t> result;

    SECTION("1")
    {
        const char *data = "The quick brown fox jumps over the lazy dog";
        ConstArray<byte_t> content(reinterpret_cast<const uint8_t*>(data), PxConstStringHelper::length(data));
        sha1.update(content);
        sha1.digest(result);
        {   ManagedStringBuffer buffer(output);
            Utf8OutputStream stream(buffer);
            stream.write(result);
        }

        REQUIRE(toStdString(output) == "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12");
    }  
    
    SECTION("2")
    {
        const char *data = "The quick brown fox jumps over the lazy cog";
        ConstArray<byte_t> content(reinterpret_cast<const uint8_t*>(data), PxConstStringHelper::length(data));
        sha1.update(content);
        sha1.digest(result);
        {   ManagedStringBuffer buffer(output);
            Utf8OutputStream stream(buffer);
            stream.write(result);
        }

        REQUIRE(toStdString(output) == "DE9F2C7FD25E1B3AFAD3E85A0BD17D9B100DB4B3");
    }
}
