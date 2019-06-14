#include <PonyTech-FND-Crypto/encrypt/Chacha20.hpp>
#include <PonyTech-LowLevel-Crypto/PonyTech-LowLevel-Crypto.h>

BEGIN_NAMESPACE(FND)
BEGIN_NAMESPACE(Crypto)

Chacha20:: Chacha20()
{
    //if no argument passed in, assume both key and nounce as 0;
    uint8_t keyin[32];
    for(size_t i=0; i < 32; i++)
    {
        keyin[i] = 0;
    }
    static_assert(sizeof(crypto_chacha20_t) <= k_size, "Size of data for low level is too small");
    crypto_chacha20_init(static_cast<crypto_chacha20_t*>(non_const_ptr()), keyin, 0);
}

Chacha20:: Chacha20(const PxConstArray<byte_t> &key, uint64_t nounce)
{
    if (key.count()!= 32) throw Exception::InvalidOperation();    

    static_assert(sizeof(crypto_chacha20_t) <= k_size, "Size of data for low level is too small");
    crypto_chacha20_init(static_cast<crypto_chacha20_t*>(non_const_ptr()), (uint8_t*)key.ptr(), nounce);
}

void Chacha20::crypto(PxConstArray<byte_t>& input, PxResizableArray<byte_t>& output)
{
    auto size = input.count();
    output.at_least(size,size);
    output.resize(size);
    crypto_chacha20_crypto(static_cast<crypto_chacha20_t*>(non_const_ptr()), input.ptr(), output.ptr(), size);
}

END_NAMESPACE(Crypto)
END_NAMESPACE(FND)
