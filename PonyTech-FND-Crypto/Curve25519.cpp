#include <PonyTech-FND-Crypto/PonyTech-FND-Crypto.hpp>
#include "../catch.hpp"
#include "../StdStringHelper.hpp"
using namespace FND;
using namespace FND::Crypto;

TEST_CASE("Testing Curve25519 - Ariana's and Blake's key","[crypto]")
{       
    const char *base_ptr = "00000000000000000000000000000000";
    ConstArray<byte_t>base_point(reinterpret_cast<const byte_t*>(base_ptr), PxConstStringHelper::length(base_ptr));

    // mine
    const char *my_private_key = "30000000000000000000000000000000";
    ConstArray<byte_t>mine_private(reinterpret_cast<const byte_t*>(my_private_key), PxConstStringHelper::length(my_private_key));

    Array<byte_t> mine_public;
    Curve25519::generate_public_key(mine_public, mine_private, base_point);

    // her 

    const char *her_private_key = "50000000000000000000000000000000";
    ConstArray<byte_t>her_private(reinterpret_cast<const byte_t*>(her_private_key), PxConstStringHelper::length(her_private_key));
    Array<byte_t> her_public;
    Curve25519::generate_public_key(her_public, her_private, base_point);

    // mine
    Array<byte_t> mine_shared;
    Curve25519::calculate_shared_key(mine_shared, mine_private, her_public);

    // her
    Array<byte_t> her_shared;
    Curve25519::calculate_shared_key(her_shared, her_private, mine_public);

    String Arianas_key = ConstString(reinterpret_cast<const char*>(her_shared.ptr()), her_shared.count());
    String Blakes_key = ConstString(reinterpret_cast<const char*>(mine_shared.ptr()), mine_shared.count());
    
    REQUIRE(toStdString(Arianas_key) == toStdString(Blakes_key));    
}
TEST_CASE("Testing Curve25519 - Non zero basepoint","[crypto]")
{       
    const char *base_ptr = "90000000000000000000000000000000";
    ConstArray<byte_t>base_point(reinterpret_cast<const byte_t*>(base_ptr), PxConstStringHelper::length(base_ptr));

    // mine
    const char *my_private_key = "30000000000000000000000000000000";
    ConstArray<byte_t>mine_private(reinterpret_cast<const byte_t*>(my_private_key), PxConstStringHelper::length(my_private_key));

    Array<byte_t> mine_public;
    Curve25519::generate_public_key(mine_public, mine_private, base_point);

    // her 

    const char *her_private_key = "50000000000000000000000000000000";
    ConstArray<byte_t>her_private(reinterpret_cast<const byte_t*>(her_private_key), PxConstStringHelper::length(her_private_key));
    Array<byte_t> her_public;
    Curve25519::generate_public_key(her_public, her_private, base_point);

    // mine
    Array<byte_t> mine_shared;
    Curve25519::calculate_shared_key(mine_shared, mine_private, her_public);

    // her
    Array<byte_t> her_shared;
    Curve25519::calculate_shared_key(her_shared, her_private, mine_public);

    String Arianas_key = ConstString(reinterpret_cast<const char*>(her_shared.ptr()), her_shared.count());
    String Blakes_key = ConstString(reinterpret_cast<const char*>(mine_shared.ptr()), mine_shared.count());
    
    REQUIRE(toStdString(Arianas_key) == toStdString(Blakes_key));    
}