#include <PonyTech-FND-Crypto/hash/SipHash24.hpp>

BEGIN_NAMESPACE(FND)
BEGIN_NAMESPACE(Crypto)

static uint64_t sipget(const byte_t *data)
{
	uint64_t v = 0;
	for (auto i = 0; i < 8; i++)
	{
		v |= static_cast<uint64_t>(data[i]) << (i << 3);
	}
	return v;
}

static uint64_t siprotate(uint64_t v, int shift)
{
    return (v << shift) | (v >> (64 - shift));
}

static void sipround(uint64_t& v0, uint64_t& v1, uint64_t& v2, uint64_t& v3, int shift1, int shift2)
{
	v0 += v1;
	v1 = siprotate(v1, shift1);
	v1 ^= v0;
	v0 = siprotate(v0, 32);

	v2 += v3;
	v3 = siprotate(v3, shift2);
	v3 ^= v2;
}

static void sipcompress(uint64_t& v0, uint64_t& v1, uint64_t& v2, uint64_t& v3, uint64_t m, int times)
{
	v3 ^= m;
	for(int i=0; i<times; i++)
	{
		sipround(v0, v1, v2, v3, 13, 16);
		sipround(v2, v1, v0, v3, 17, 21);
	}
	v0 ^= m;
}

SipHash24::SipHash24(const byte_t* key) 
{
	static_assert(sizeof(SipHash24::Entity) <= DataConstant::k_hash_64_size * sizeof(uint64_t), 
            "This content is smaller than platform specific");

	m_data.data.k0 = sipget(key);
	m_data.data.k1 = sipget(key + 8);
	m_data.data.v[0] = m_data.data.k0 ^ 0x736f6d6570736575ULL;
	m_data.data.v[1] = m_data.data.k1 ^ 0x646f72616e646f6dULL;
	m_data.data.v[2] = m_data.data.k0 ^ 0x6c7967656e657261ULL;
	m_data.data.v[3] = m_data.data.k1 ^ 0x7465646279746573ULL;
    
    m_data.data.index = 0;
	m_data.data.length = 0;
	m_data.data.storage = 0;
}

void SipHash24::update(const byte_t *data, size_t len)
{
	m_data.data.length += static_cast<uint64_t>(len);
	auto end = data + len;

	for(;;)
	{
		for(; m_data.data.index <8 && data < end; m_data.data.index++, data++)
		{
			m_data.data.storage |= static_cast<uint64_t>(*data) << (m_data.data.index << 3);
		}
		if (m_data.data.index < 8) break;

		sipcompress(m_data.data.v[0], m_data.data.v[1], m_data.data.v[2], m_data.data.v[3], m_data.data.storage, 2);
		m_data.data.storage = 0;
		m_data.data.index = 0;
	}
}

uint64_t SipHash24::digest() const
{
	constexpr int c = 2;
	constexpr int d = 4;
	uint64_t b = m_data.data.storage | (static_cast<uint64_t>(m_data.data.length) << 56);
	uint64_t v0 = m_data.data.v[0];
	uint64_t v1 = m_data.data.v[1];
	uint64_t v2 = m_data.data.v[2];
	uint64_t v3 = m_data.data.v[3];

	sipcompress(v0, v1, v2, v3, b, c);

 	v2 ^= 0xff;
	for(int i=0; i<d; i++)
	{
		sipround(v0, v1, v2, v3, 13, 16);
		sipround(v2, v1, v0, v3, 17, 21);
	}
	return v0 ^ v1 ^ v2 ^ v3;
}

static byte_t s_key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

static void hash_init(uint64_t *buffer)
{
	auto hash = reinterpret_cast<SipHash24*>(buffer);
	new (hash) SipHash24(s_key);
}
static void hash_update(const byte_t* data, size_t len, uint64_t *buffer)
{
	auto hash = reinterpret_cast<SipHash24*>(buffer);
	hash->update(data,len);
}
static uint64_t hash_digest(uint64_t *buffer)
{
	auto hash = reinterpret_cast<SipHash24*>(buffer);
	return hash->digest();
}

void SipHash24::register_hash()
{
	Hash::Handle handle;
	handle.init   = hash_init;
	handle.update = hash_update;
	handle.digest = hash_digest;
	Hash::register_handle(handle);
}

END_NAMESPACE(Crypto)
END_NAMESPACE(FND)
