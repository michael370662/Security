#include <PonyTech-FND-Crypto/PonyTech-FND-Crypto.hpp>
#include "../catch.hpp"
#include "../StdStringHelper.hpp"

using namespace FND;
using namespace FND::Crypto;

TEST_CASE("Testing MD5 - empty", "[crypto]")
{
    String output;
    MD5 md5;
    Array<byte_t> result;

    md5.digest(result);
    {   ManagedStringBuffer buffer(output);
        Utf8OutputStream stream(buffer);
        stream.write(result);
    }

    REQUIRE(toStdString(output) == "D41D8CD98F00B204E9800998ECF8427E");
}

TEST_CASE("Testing MD5 - test vector ", "[crypto]")
{
    String output;
    MD5 md5;
    Array<byte_t> result;

    SECTION("abc")
    {
        const char *data = "abc";
        ConstArray<byte_t> content(reinterpret_cast<const uint8_t*>(data), PxConstStringHelper::length(data));
        md5.update(content);
        md5.digest(result);
        {   ManagedStringBuffer buffer(output);
            Utf8OutputStream stream(buffer);
            stream.write(result);
        }

        REQUIRE(toStdString(output) == "900150983CD24FB0D6963F7D28E17F72");
    }
    SECTION("long abc")
    {
        const char *data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        ConstArray<byte_t> content(reinterpret_cast<const uint8_t*>(data), PxConstStringHelper::length(data));
        md5.update(content);
        md5.digest(result);
        {   ManagedStringBuffer buffer(output);
            Utf8OutputStream stream(buffer);
            stream.write(result);
        }
        REQUIRE(toStdString(output) == "8215EF0796A20BCAAAE116D3876C664A");
    }  
}


TEST_CASE("Testing MD5 - wiki", "[crypto]")
{
    String output;
    MD5 md5;
    Array<byte_t> result;

    SECTION("1")
    {
        const char *data = "The quick brown fox jumps over the lazy dog";
        ConstArray<byte_t> content(reinterpret_cast<const uint8_t*>(data), PxConstStringHelper::length(data));
        md5.update(content);
        md5.digest(result);
        {   ManagedStringBuffer buffer(output);
            Utf8OutputStream stream(buffer);
            stream.write(result);
        }

        REQUIRE(toStdString(output) == "9E107D9D372BB6826BD81D3542A419D6");
    }  
    
    SECTION("2")
    {
        const char *data = "The quick brown fox jumps over the lazy cog";
        ConstArray<byte_t> content(reinterpret_cast<const uint8_t*>(data), PxConstStringHelper::length(data));
        md5.update(content);
        md5.digest(result);
        {   ManagedStringBuffer buffer(output);
            Utf8OutputStream stream(buffer);
            stream.write(result);
        }

        REQUIRE(toStdString(output) == "1055D3E698D289F2AF8663725127BD4B");
    }
}
