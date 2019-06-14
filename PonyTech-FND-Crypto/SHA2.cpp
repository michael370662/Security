#include <PonyTech-FND-Crypto/PonyTech-FND-Crypto.hpp>
#include "../catch.hpp"
#include "../StdStringHelper.hpp"

using namespace FND;
using namespace FND::Crypto;

TEST_CASE("Testing SHA2 - empty", "[crypto]")
{
    String output;
    SECTION("28")
    {
        SHA2 sha2(SHA2::Type::key_224);
        Array<byte_t> result;

        sha2.digest(result);
        {   
            ManagedStringBuffer buffer(output);
            Utf8OutputStream stream(buffer);
            stream.write(result);
        }
        REQUIRE(toStdString(output) == "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F");
    }

    SECTION("32")
    {
        SHA2 sha2(SHA2::Type::key_256);
        Array<byte_t> result;

        sha2.digest(result);
        {   
            ManagedStringBuffer buffer(output);
            Utf8OutputStream stream(buffer);
            stream.write(result);
        }
        REQUIRE(toStdString(output) == "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
    }

    SECTION("48")
    {
        SHA2 sha2(SHA2::Type::key_384);
        Array<byte_t> result;

        sha2.digest(result);
        {   
            ManagedStringBuffer buffer(output);
            Utf8OutputStream stream(buffer);
            stream.write(result);
        }
        REQUIRE(toStdString(output) == "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B");
    }

    SECTION("64")
    {
        SHA2 sha2(SHA2::Type::key_512);
        Array<byte_t> result;

        sha2.digest(result);
        {   
            ManagedStringBuffer buffer(output);
            Utf8OutputStream stream(buffer);
            stream.write(result);
        }
        REQUIRE(toStdString(output) ==  "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E");
    }    
}

TEST_CASE("Testing SHA2 - test vector ", "[crypto]")
{
    String output;
    Array<byte_t> result;

    SECTION("abc")
    {
        const char *data = "abc";
        ConstArray<byte_t> content(reinterpret_cast<const uint8_t*>(data), PxConstStringHelper::length(data));
        SECTION("28")
        {
            SHA2 sha2(SHA2::Type::key_224);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) == "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7");
        }

        SECTION("32")
        {
            SHA2 sha2(SHA2::Type::key_256);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
        }

        SECTION("48")
        {
            SHA2 sha2(SHA2::Type::key_384);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) == "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7");
        }       

        SECTION("64")
        {   
            SHA2 sha2(SHA2::Type::key_512);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) ==  "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F");
        }    
    }
    SECTION("long abc")
    {
        const char *data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        ConstArray<byte_t> content(reinterpret_cast<const uint8_t*>(data), PxConstStringHelper::length(data));
        SECTION("28")
        {
            SHA2 sha2(SHA2::Type::key_224);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) == "75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525");
        }

        SECTION("32")
        {
            SHA2 sha2(SHA2::Type::key_256);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) == "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1");
        }

        SECTION("48")
        {
            SHA2 sha2(SHA2::Type::key_384);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) == "3391FDDDFC8DC7393707A65B1B4709397CF8B1D162AF05ABFE8F450DE5F36BC6B0455A8520BC4E6F5FE95B1FE3C8452B");
        }       

        SECTION("64")
        {   
            SHA2 sha2(SHA2::Type::key_512);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) ==  "204A8FC6DDA82F0A0CED7BEB8E08A41657C16EF468B228A8279BE331A703C33596FD15C13B1B07F9AA1D3BEA57789CA031AD85C7A71DD70354EC631238CA3445");
        }    
    }
    SECTION("long long abc")
    {
        const char *data = "abcdefghijklmnopqrstvwxyzabcdefghijklmnopqrstvwxyzabcdefghijklmnopqrstvwxyzabcdefghijklmnopqrstvwxyzabcdefghijklmnopqrstvwx";
        ConstArray<byte_t> content(reinterpret_cast<const uint8_t*>(data), PxConstStringHelper::length(data));
        SECTION("28")
        {
            SHA2 sha2(SHA2::Type::key_224);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) == "678F71446E1AA7E4D1C0DFF0C0C58C686BBF692D4F963AB4F234EA12");
        }

        SECTION("32")
        {
            SHA2 sha2(SHA2::Type::key_256);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) == "C7491F64DE36A89BB2A3C7FBD8F58B03A3053BB143CEC13E29ED08A1974CFF2A");
        }

        SECTION("48")
        {
            SHA2 sha2(SHA2::Type::key_384);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) == "14A9D9BF6178A9413FEA0D127968F8BDB2312E117CECE315F8B5E160C18A43954E06027EF348DBA891E8814BDCFBCE5A");
        }       

        SECTION("64")
        {   
            SHA2 sha2(SHA2::Type::key_512);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) ==  "245114214365C5045DA144B083EE1FF11FD346F3096D08867518620ACAA3BB9D447BC2446C2997986BEA9C37CEEB9D8DC4200C31EAF12C2E41D8A9DC537A2749");
        }    
    }  
}


TEST_CASE("Testing SHA2 - wiki", "[crypto]")
{
    String output;
    Array<byte_t> result;

    SECTION("1")
    {
        const char *data = "The quick brown fox jumps over the lazy dog";
        ConstArray<byte_t> content(reinterpret_cast<const uint8_t*>(data), PxConstStringHelper::length(data));
        SECTION("28")
        {
            SHA2 sha2(SHA2::Type::key_224);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) == "730E109BD7A8A32B1CB9D9A09AA2325D2430587DDBC0C38BAD911525");
        }

        SECTION("32")
        {
            SHA2 sha2(SHA2::Type::key_256);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) == "D7A8FBB307D7809469CA9ABCB0082E4F8D5651E46D3CDB762D02D0BF37C9E592");
        }

        SECTION("48")
        {
            SHA2 sha2(SHA2::Type::key_384);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) == "CA737F1014A48F4C0B6DD43CB177B0AFD9E5169367544C494011E3317DBF9A509CB1E5DC1E85A941BBEE3D7F2AFBC9B1");
        }       

        SECTION("64")
        {   
            SHA2 sha2(SHA2::Type::key_512);
            Array<byte_t> result;
            sha2.update(content);
            sha2.digest(result);
            {   
                ManagedStringBuffer buffer(output);
                Utf8OutputStream stream(buffer);
                stream.write(result);
            }
            REQUIRE(toStdString(output) ==  "07E547D9586F6A73F73FBAC0435ED76951218FB7D0C8D788A309D785436BBB642E93A252A954F23912547D1E8A3B5ED6E1BFD7097821233FA0538F3DB854FEE6");
        }  
    }  
}
