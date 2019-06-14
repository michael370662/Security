#include <PonyTech-FND-Crypto/encrypt/Curve25519.hpp>
#include <PonyTech-LowLevel-Crypto/PonyTech-LowLevel-Crypto.h>

BEGIN_NAMESPACE(FND)
BEGIN_NAMESPACE(Crypto)

void Curve25519::generate_public_key(PxResizableArray<byte_t>& self_public_key, PxConstArray<byte_t>& self_private_key, PxConstArray<byte_t>& base_point)
{
    if (self_private_key.count()!= PubKeyCurve25519Size) throw Exception::InvalidOperation();    
    
    self_public_key.at_least(PubKeyCurve25519Size,PubKeyCurve25519Size);
    self_public_key.resize(PubKeyCurve25519Size);
    crypto_curve25519(self_public_key.ptr(),  self_private_key.ptr(), base_point.ptr());
}

void Curve25519::calculate_shared_key(PxResizableArray<byte_t>& self_shared_key, PxConstArray<byte_t>& self_private_key, PxConstArray<byte_t>& peer_public_key)
{
    if (self_private_key.count()!= PubKeyCurve25519Size) throw Exception::InvalidOperation();    

    self_shared_key.at_least(PubKeyCurve25519Size,PubKeyCurve25519Size);
    self_shared_key.resize(PubKeyCurve25519Size);
    crypto_curve25519(self_shared_key.ptr(), self_private_key.ptr(), peer_public_key.ptr());
}



END_NAMESPACE(Crypto)
END_NAMESPACE(FND)
