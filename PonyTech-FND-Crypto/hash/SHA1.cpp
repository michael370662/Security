#include <PonyTech-FND-Crypto/hash/SHA1.hpp>
#include <PonyTech-LowLevel-Crypto/PonyTech-LowLevel-Crypto.h>

BEGIN_NAMESPACE(FND)
BEGIN_NAMESPACE(Crypto)

SHA1::SHA1()
{
    static_assert(sizeof(crypto_sha1_t) <= k_size, "Size of data for low level is too small");
    static_assert(DSIZE_SHA1_RESULT <= k_result_size, "Size of data for low level is too small");
    crypto_sha1_init(static_cast<crypto_sha1_t*>(non_const_ptr()));
}
    
void SHA1::update(const PxConstArray<byte_t>& content)
{
    crypto_sha1_update(static_cast<crypto_sha1_t*>(non_const_ptr()), content.ptr(), content.count());
}

void SHA1::digest(PxResizableArray<byte_t>& result)
{
    result.at_least(k_result_size, k_result_size);
    result.resize(k_result_size);
    crypto_sha1_final(static_cast<crypto_sha1_t*>(non_const_ptr()), result.ptr(), k_result_size);
}

END_NAMESPACE(Crypto)
END_NAMESPACE(FND)