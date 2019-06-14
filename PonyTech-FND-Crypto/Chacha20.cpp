#include <PonyTech-FND-Crypto/PonyTech-FND-Crypto.hpp>
#include "../catch.hpp"
#include "../StdStringHelper.hpp"

using namespace FND;
using namespace FND::Crypto;


TEST_CASE("Testing Chacha20 - same key same nounce","[crypto]")
{       
    const char *data = "The quick brown fox jumps over the lazy dog";
    ConstArray<byte_t>content(reinterpret_cast<const byte_t*>(data), PxConstStringHelper::length(data));
    const char *keyin = "00000000000001000000000000000000";
    ConstArray<byte_t>key(reinterpret_cast<const byte_t*>(keyin), PxConstStringHelper::length(keyin));

    Array<byte_t> crypto_text;
    { 
        Chacha20 chacha20(key,0);
        chacha20.crypto(content, crypto_text);
    }
    Array<byte_t> crypto_text_1;
    { 
        Chacha20 chacha20(key,0);
        chacha20.crypto(content, crypto_text_1);
    }
    String output = ConstString(reinterpret_cast<const char*>(crypto_text.ptr()), crypto_text.count());
    String output_1 = ConstString(reinterpret_cast<const char*>(crypto_text_1.ptr()), crypto_text_1.count());
    REQUIRE(toStdString(output) == toStdString(output_1));    
}

TEST_CASE("Testing Chacha20 - same key diff nounce","[crypto]")
{
    const char *data = "The quick brown fox jumps over the lazy dog";
    ConstArray<byte_t>content(reinterpret_cast<const byte_t*>(data), PxConstStringHelper::length(data));
    const char *keyin = "00000000000001000000000000000000";
    ConstArray<byte_t>key(reinterpret_cast<const byte_t*>(keyin), PxConstStringHelper::length(keyin));

    Array<byte_t> crypto_text;
    { 
        Chacha20 chacha20(key,0);
        chacha20.crypto(content, crypto_text);
    }
    Array<byte_t> crypto_text_1;
    { 
        Chacha20 chacha20(key,1);
        chacha20.crypto(content, crypto_text_1);
    }
    String output = ConstString(reinterpret_cast<const char*>(crypto_text.ptr()), crypto_text.count());
    String output_1 = ConstString(reinterpret_cast<const char*>(crypto_text_1.ptr()), crypto_text_1.count());
    REQUIRE(toStdString(output) != toStdString(output_1));
}

TEST_CASE("Testing Chacha20 - diff key same nounce","[crypto]")
{
    const char *data = "The quick brown fox jumps over the lazy dog";
    ConstArray<byte_t>content(reinterpret_cast<const byte_t*>(data), PxConstStringHelper::length(data));
    const char *keyin = "00000000000001000000000000000000";
    ConstArray<byte_t>key(reinterpret_cast<const byte_t*>(keyin), PxConstStringHelper::length(keyin));

    Array<byte_t> crypto_text;
    { 
        Chacha20 chacha20(key,0);
        chacha20.crypto(content, crypto_text);
    }
    Array<byte_t> crypto_text_1;
    { 
        Chacha20 chacha20;
        chacha20.crypto(content, crypto_text_1);
    }
    String output = ConstString(reinterpret_cast<const char*>(crypto_text.ptr()), crypto_text.count());
    String output_1 = ConstString(reinterpret_cast<const char*>(crypto_text_1.ptr()), crypto_text_1.count());
    REQUIRE(toStdString(output) != toStdString(output_1));
}

TEST_CASE("Testing Chacha20 - diff key diff nounce","[crypto]")
{
    const char *data = "The quick brown fox jumps over the lazy dog";
    ConstArray<byte_t>content(reinterpret_cast<const byte_t*>(data), PxConstStringHelper::length(data));
    const char *keyin = "00000000000001000000000000000000";
    ConstArray<byte_t>key(reinterpret_cast<const byte_t*>(keyin), PxConstStringHelper::length(keyin));

    Array<byte_t> crypto_text;
    { 
        Chacha20 chacha20(key,1);
        chacha20.crypto(content, crypto_text);
    }
    Array<byte_t> crypto_text_1;
    { 
        Chacha20 chacha20;
        chacha20.crypto(content, crypto_text_1);
    }
    String output = ConstString(reinterpret_cast<const char*>(crypto_text.ptr()), crypto_text.count());
    String output_1 = ConstString(reinterpret_cast<const char*>(crypto_text_1.ptr()), crypto_text_1.count());
    REQUIRE(toStdString(output) != toStdString(output_1));
}

TEST_CASE("Testing Chacha20 - empty", "[crypto]")
{
    const char *data = "";
    ConstArray<byte_t>content(reinterpret_cast<const byte_t*>(data), PxConstStringHelper::length(data));

    Array<byte_t> crypto_text,plain_text;
    { 
        Chacha20 chacha20;
        chacha20.crypto(content, crypto_text);
    }
    {
        Chacha20 chacha20;
        chacha20.crypto(crypto_text, plain_text);
    }

    String output = ConstString(reinterpret_cast<const char*>(plain_text.ptr()), plain_text.count());
    REQUIRE(toStdString(output) == "");
}

TEST_CASE("Testing Chacha20 - wiki", "[crypto]")
{
    SECTION("1")
    {
        const char *data = "The quick brown fox jumps over the lazy dog";
        ConstArray<byte_t>content(reinterpret_cast<const byte_t*>(data), PxConstStringHelper::length(data));

        Array<byte_t> crypto_text,plain_text;
        { 
            Chacha20 chacha20;
            chacha20.crypto(content, crypto_text);
        }
        {
            Chacha20 chacha20;
            chacha20.crypto(crypto_text, plain_text);
        }

        String output = ConstString(reinterpret_cast<const char*>(plain_text.ptr()), plain_text.count());
        REQUIRE(toStdString(output) == "The quick brown fox jumps over the lazy dog");
    }
    
    SECTION("2")
    {
        const char *data = "The quick brown fox jumps over the lazy cog";
        ConstArray<byte_t>content(reinterpret_cast<const byte_t*>(data), PxConstStringHelper::length(data));

        Array<byte_t> crypto_text,plain_text;
        { 
            Chacha20 chacha20;
            chacha20.crypto(content, crypto_text);
        }
        {
            Chacha20 chacha20;
            chacha20.crypto(crypto_text, plain_text);
        }

        String output = ConstString(reinterpret_cast<const char*>(plain_text.ptr()), plain_text.count());
        REQUIRE(toStdString(output) == "The quick brown fox jumps over the lazy cog");
    }
        SECTION("3")
    {
        const char *data = "abcdefghijklmnopqrstvwxyzabcdefghijklmnopqrstvwxyzabcdefghijklmnopqrstvwxyzabcdefghijklmnopqrstvwxyzabcdefghijklmnopqrstvwxyz";
        ConstArray<byte_t>content(reinterpret_cast<const byte_t*>(data), PxConstStringHelper::length(data));

        Array<byte_t> crypto_text,plain_text;
        { 
            Chacha20 chacha20;
            chacha20.crypto(content, crypto_text);
        }
        {
            Chacha20 chacha20;
            chacha20.crypto(crypto_text, plain_text);
        }

        String output = ConstString(reinterpret_cast<const char*>(plain_text.ptr()), plain_text.count());
        REQUIRE(toStdString(output) == "abcdefghijklmnopqrstvwxyzabcdefghijklmnopqrstvwxyzabcdefghijklmnopqrstvwxyzabcdefghijklmnopqrstvwxyzabcdefghijklmnopqrstvwxyz");
    }

}
