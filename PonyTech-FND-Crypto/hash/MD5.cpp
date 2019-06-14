#include <PonyTech-FND-Crypto/hash/MD5.hpp>
#include <PonyTech-LowLevel-Crypto/PonyTech-LowLevel-Crypto.h>

BEGIN_NAMESPACE(FND)
BEGIN_NAMESPACE(Crypto)

MD5::MD5()
{
    static_assert(sizeof(crypto_md5_t) <= k_size, "Size of data for low level is too small");
    static_assert(DSIZE_MD5_RESULT <= k_result_size, "Size of data for low level is too small");
    crypto_md5_init(static_cast<crypto_md5_t*>(non_const_ptr()));
}
    
void MD5::update(const PxConstArray<byte_t>& content)
{
    crypto_md5_update(static_cast<crypto_md5_t*>(non_const_ptr()), content.ptr(), content.count());
}

void MD5::digest(PxResizableArray<byte_t>& result)
{
    result.at_least(k_result_size, k_result_size);
    result.resize(k_result_size);
    crypto_md5_final(result.ptr(), static_cast<crypto_md5_t*>(non_const_ptr()), k_result_size);
}

END_NAMESPACE(Crypto)
END_NAMESPACE(FND)