#include <PonyTech-FND-Crypto/hash/SHA2.hpp>
#include <PonyTech-LowLevel-Crypto/PonyTech-LowLevel-Crypto.h>

BEGIN_NAMESPACE(FND)
BEGIN_NAMESPACE(Crypto)

SHA2::SHA2(Type type)
{
    m_size = type;
    static_assert(sizeof(crypto_sha2_t) <= k_size, "Size of data for low level is too small");
    switch(type)
    {

        case Type::key_224:
        {
            crypto_sha224_init(static_cast<crypto_sha2_t*>(non_const_ptr()));
        }
        break;
         case Type::key_256:
        {
            crypto_sha256_init(static_cast<crypto_sha2_t*>(non_const_ptr()));     
        }
        break;
         case Type::key_384:
        {
            crypto_sha384_init(static_cast<crypto_sha2_t*>(non_const_ptr()));
        }
        break;
        default:
        {
            crypto_sha512_init(static_cast<crypto_sha2_t*>(non_const_ptr()));  
        }
    
    }

    
}
    
void SHA2::update(const PxConstArray<byte_t>& content)
{    
    switch(m_size)
    {
        case Type::key_224:
        {
            crypto_sha224_update(static_cast<crypto_sha2_t*>(non_const_ptr()), content.ptr(), content.count());            
        }
        break;
        case Type::key_256:
        {
            crypto_sha256_update(static_cast<crypto_sha2_t*>(non_const_ptr()), content.ptr(), content.count());
        }
        break;
        case Type::key_384:
        {
            crypto_sha384_update(static_cast<crypto_sha2_t*>(non_const_ptr()), content.ptr(), content.count());            
        }
        break;
        default:
            crypto_sha512_update(static_cast<crypto_sha2_t*>(non_const_ptr()), content.ptr(), content.count());

    }
}

void SHA2::digest(PxResizableArray<byte_t>& result)
{
    result.at_least(m_size, m_size);
    result.resize(m_size);

    switch(m_size)
    {
        case Type::key_224:
        {
            crypto_sha224_final(static_cast<crypto_sha2_t*>(non_const_ptr()), result.ptr());          
        }
        break;
        case Type::key_256:
        {
            crypto_sha256_final(static_cast<crypto_sha2_t*>(non_const_ptr()), result.ptr());        
        }
        break;
        case Type::key_384:
        {
            crypto_sha384_final(static_cast<crypto_sha2_t*>(non_const_ptr()), result.ptr());          
        }
        break;
        default:
            crypto_sha512_final(static_cast<crypto_sha2_t*>(non_const_ptr()), result.ptr());
    }    
}

END_NAMESPACE(Crypto)
END_NAMESPACE(FND)