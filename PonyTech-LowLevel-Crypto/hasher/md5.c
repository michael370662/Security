#include <PonyTech-LowLevel-Crypto/hasher.h>
#include "../PonyTech-LowLevel-Crypto_DEP.h"
//http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5



// The basic MD5 functions.

// F and G are optimized compared to their RFC 1321 definitions for
// architectures that lack an AND-NOT instruction, just like in Colin Plumb's
// implementation.

#define F(_x, _y, _z)			((_z) ^ ((_x) & ((_y) ^ (_z))))
#define G(_x, _y, _z)			((_y) ^ ((_z) & ((_x) ^ (_y))))
#define H(_x, _y, _z)			(((_x) ^ (_y)) ^ (_z))
#define H2(_x, _y, _z)			((_x) ^ ((_y) ^ (_z)))
#define I(_x, _y, _z)			((_y) ^ ((_x) | ~(_z)))

//
// The MD5 transformation for all four rounds.
//
#define STEP(_f, _a, _b, _c, _d, _x, _t, _s) \
	(_a) += _f((_b), (_c), (_d)) + (_x) + (_t); \
	(_a) = (((_a) << (_s)) | (((_a) & 0xffffffff) >> (32 - (_s)))); \
	(_a) += (_b);


#define GET(_buffer, _n) (_buffer[(_n)])


//
// This processes one or more 64-byte data blocks, but does NOT update the bit
// counters.  There are no alignment requirements.
//
static const void *crypto_md5_logic(crypto_md5_t *self, const void *data, size_t size)
{
	const uint8_t *ptr;
	uint32_t a, b, c, d;

	ptr = (const uint8_t *)data;

	a = self->a;
	b = self->b;
	c = self->c;
	d = self->d;

	do {
		uint32_t state_a, state_b, state_c, state_d;
		state_a = a;
		state_b = b;
		state_c = c;
		state_d = d;
		uint32_t buffer[16];

		for(size_t i = 0; i < 16; ++i)
		{
			buffer[i] = basic_byte_swap_l32((*(const uint32_t*)&ptr[i*4]), self->little_endian);
		}

// Round 1
		STEP(F, a, b, c, d, GET(buffer, 0),  0xd76aa478, 7)
		STEP(F, d, a, b, c, GET(buffer, 1),  0xe8c7b756, 12)
		STEP(F, c, d, a, b, GET(buffer, 2),  0x242070db, 17)
		STEP(F, b, c, d, a, GET(buffer, 3),  0xc1bdceee, 22)
		STEP(F, a, b, c, d, GET(buffer, 4),  0xf57c0faf, 7)
		STEP(F, d, a, b, c, GET(buffer, 5),  0x4787c62a, 12)
		STEP(F, c, d, a, b, GET(buffer, 6),  0xa8304613, 17)
		STEP(F, b, c, d, a, GET(buffer, 7),  0xfd469501, 22)
		STEP(F, a, b, c, d, GET(buffer, 8),  0x698098d8, 7)
		STEP(F, d, a, b, c, GET(buffer, 9),  0x8b44f7af, 12)
		STEP(F, c, d, a, b, GET(buffer, 10), 0xffff5bb1, 17)
		STEP(F, b, c, d, a, GET(buffer, 11), 0x895cd7be, 22)
		STEP(F, a, b, c, d, GET(buffer, 12), 0x6b901122, 7)
		STEP(F, d, a, b, c, GET(buffer, 13), 0xfd987193, 12)
		STEP(F, c, d, a, b, GET(buffer, 14), 0xa679438e, 17)
		STEP(F, b, c, d, a, GET(buffer, 15), 0x49b40821, 22)

// Round 2
		STEP(G, a, b, c, d, GET(buffer, 1),  0xf61e2562, 5)
		STEP(G, d, a, b, c, GET(buffer, 6),  0xc040b340, 9)
		STEP(G, c, d, a, b, GET(buffer, 11), 0x265e5a51, 14)
		STEP(G, b, c, d, a, GET(buffer, 0),  0xe9b6c7aa, 20)
		STEP(G, a, b, c, d, GET(buffer, 5),  0xd62f105d, 5)
		STEP(G, d, a, b, c, GET(buffer, 10), 0x02441453, 9)
		STEP(G, c, d, a, b, GET(buffer, 15), 0xd8a1e681, 14)
		STEP(G, b, c, d, a, GET(buffer, 4),  0xe7d3fbc8, 20)
		STEP(G, a, b, c, d, GET(buffer, 9),  0x21e1cde6, 5)
		STEP(G, d, a, b, c, GET(buffer, 14), 0xc33707d6, 9)
		STEP(G, c, d, a, b, GET(buffer, 3),  0xf4d50d87, 14)
		STEP(G, b, c, d, a, GET(buffer, 8),  0x455a14ed, 20)
		STEP(G, a, b, c, d, GET(buffer, 13), 0xa9e3e905, 5)
		STEP(G, d, a, b, c, GET(buffer, 2),  0xfcefa3f8, 9)
		STEP(G, c, d, a, b, GET(buffer, 7),  0x676f02d9, 14)
		STEP(G, b, c, d, a, GET(buffer, 12), 0x8d2a4c8a, 20)

//Round 3
		STEP(H, a, b, c, d, GET(buffer, 5),  0xfffa3942, 4)
		STEP(H2, d, a, b, c,GET(buffer, 8),  0x8771f681, 11)
		STEP(H, c, d, a, b, GET(buffer, 11), 0x6d9d6122, 16)
		STEP(H2, b, c, d, a,GET(buffer, 14), 0xfde5380c, 23)
		STEP(H, a, b, c, d, GET(buffer, 1),  0xa4beea44, 4)
		STEP(H2, d, a, b, c,GET(buffer, 4),  0x4bdecfa9, 11)
		STEP(H, c, d, a, b, GET(buffer, 7),  0xf6bb4b60, 16)
		STEP(H2, b, c, d, a,GET(buffer, 10), 0xbebfbc70, 23)
		STEP(H, a, b, c, d, GET(buffer, 13), 0x289b7ec6, 4)
		STEP(H2, d, a, b, c,GET(buffer, 0),  0xeaa127fa, 11)
		STEP(H, c, d, a, b, GET(buffer, 3),  0xd4ef3085, 16)
		STEP(H2, b, c, d, a,GET(buffer, 6),  0x04881d05, 23)
		STEP(H, a, b, c, d, GET(buffer, 9),  0xd9d4d039, 4)
		STEP(H2, d, a, b, c,GET(buffer, 12), 0xe6db99e5, 11)
		STEP(H, c, d, a, b, GET(buffer, 15), 0x1fa27cf8, 16)
		STEP(H2, b, c, d, a,GET(buffer, 2),  0xc4ac5665, 23)

// Round 4
		STEP(I, a, b, c, d, GET(buffer, 0),  0xf4292244, 6)
		STEP(I, d, a, b, c, GET(buffer, 7),  0x432aff97, 10)
		STEP(I, c, d, a, b, GET(buffer, 14), 0xab9423a7, 15)
		STEP(I, b, c, d, a, GET(buffer, 5),  0xfc93a039, 21)
		STEP(I, a, b, c, d, GET(buffer, 12), 0x655b59c3, 6)
		STEP(I, d, a, b, c, GET(buffer, 3),  0x8f0ccc92, 10)
		STEP(I, c, d, a, b, GET(buffer, 10), 0xffeff47d, 15)
		STEP(I, b, c, d, a, GET(buffer, 1),  0x85845dd1, 21)
		STEP(I, a, b, c, d, GET(buffer, 8),  0x6fa87e4f, 6)
		STEP(I, d, a, b, c, GET(buffer, 15), 0xfe2ce6e0, 10)
		STEP(I, c, d, a, b, GET(buffer, 6),  0xa3014314, 15)
		STEP(I, b, c, d, a, GET(buffer, 13), 0x4e0811a1, 21)
		STEP(I, a, b, c, d, GET(buffer, 4),  0xf7537e82, 6)
		STEP(I, d, a, b, c, GET(buffer, 11), 0xbd3af235, 10)
		STEP(I, c, d, a, b, GET(buffer, 2),  0x2ad7d2bb, 15)
		STEP(I, b, c, d, a, GET(buffer, 9),  0xeb86d391, 21)

		a += state_a;
		b += state_b;
		c += state_c;
		d += state_d;

		ptr += 64;
	} while (size -= 64);

	self->a = a;
	self->b = b;
	self->c = c;
	self->d = d;

	return ptr;
}

void crypto_md5_init(crypto_md5_t *self)
{
	self->a = 0x67452301;
	self->b = 0xefcdab89;
	self->c = 0x98badcfe;
	self->d = 0x10325476;

	self->size = 0;
	self->little_endian = basic_byte_order_is_little();
}

void crypto_md5_update(crypto_md5_t *self, const void *data, size_t size)
{
	size_t used = self->size & 0x3f;
	self->size += size;

	if (used) 
	{
		size_t available = 64 - used;

		if (size < available) 
		{
			memcpy(&self->buffer[used], data, size);
			return;
		}

		memcpy(&self->buffer[used], data, available);
		data = (const uint8_t *)data + available;
		size -= available;
		crypto_md5_logic(self, self->buffer, 64);
	}

	if (size >= 64) 
	{
		data = crypto_md5_logic(self, data, size & ~(size_t)0x3f);
		size &= 0x3f;
	}

	memcpy(self->buffer, data, size);

}


bool crypto_md5_final(uint8_t *result, crypto_md5_t *self, size_t size)
{
	if (size < DSIZE_MD5_RESULT) return false;

	size_t used = self->size & 0x3f;
	self->buffer[used++] = 0x80;

	size_t available = 64 - used;
	if (available < 8) 
	{
		memset(&self->buffer[used], 0, available);
		crypto_md5_logic(self, self->buffer, 64);
		used = 0;
		available = 64;
	}

	memset(&self->buffer[used], 0, available - 8);

	self->size <<= 3;
	*((uint64_t *) &self->buffer[56]) = basic_byte_swap_l64(self->size, true);

	crypto_md5_logic(self, self->buffer, 64);


	*((uint32_t *) (result+0))  = basic_byte_swap_l32(self->a, true);
	*((uint32_t *) (result+4))  = basic_byte_swap_l32(self->b, true);
	*((uint32_t *) (result+8))  = basic_byte_swap_l32(self->c, true);
	*((uint32_t *) (result+12)) = basic_byte_swap_l32(self->d, true);

	memset(self, 0, sizeof(*self));
	return true;
}
