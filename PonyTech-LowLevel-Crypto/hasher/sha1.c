#include <PonyTech-LowLevel-Crypto/hasher.h>
#include "../PonyTech-LowLevel-Crypto_DEP.h"

#define SHA_ROT(X,l,r)	(((X) << (l)) | ((X) >> (r)))
#define SHA_ROL(X,n)	SHA_ROT(X,n,32-(n))
#define SHA_ROR(X,n)	SHA_ROT(X,32-(n),n)

#define SHA_WS(_ws, _idx) _ws[(_idx)& 15] 
#define SHA_SWAP_SRC(_block, _ws, _t) basic_byte_swap_32(*(uint32_t*)((_block) + (_t) *4));
#define SHA_NOSWAP_SRC(_block, _ws, _t) (*(uint32_t*)((_block) + (_t) *4));
#define SHA_MIX(_block, _ws, _t) mix_value(_ws, _t);

#define SHA_SET_TEMP(_ws, _idx, _val) SHA_WS(_ws,_idx) = (_val);

#define SHA_ROUND(_block, _ws, _t, _input, _fn, _constant, A, B, C, D, E) do { \
	uint32_t _TEMP = _input(_block, _ws, _t); \
    SHA_SET_TEMP(_ws, _t, _TEMP); \
	E += _TEMP + SHA_ROL(A,5) + (_fn) + (_constant); \
	B = SHA_ROR(B, 2); } while (0);


#define RLE(_block, _ws, _t, A, B, C, D, E)  SHA_ROUND(_block, _ws, _t, SHA_SWAP_SRC, (((C^D)&B)^D) , 0x5A827999, A, B, C, D, E )
#define RBE(_block, _ws, _t, A, B, C, D, E)  SHA_ROUND(_block, _ws, _t, SHA_NOSWAP_SRC, (((C^D)&B)^D) , 0x5A827999, A, B, C, D, E )
#define R1(_block, _ws, _t, A, B, C, D, E)   SHA_ROUND(_block, _ws, _t, SHA_MIX, (((C^D)&B)^D) , 0x5A827999, A, B, C, D, E )
#define R2(_block, _ws, _t, A, B, C, D, E)   SHA_ROUND(_block, _ws, _t, SHA_MIX, (B^C^D) , 0x6ED9EBA1, A, B, C, D, E )
#define R3(_block, _ws, _t, A, B, C, D, E)   SHA_ROUND(_block, _ws, _t, SHA_MIX, ((B&C)+(D&(B^C))) , 0x8F1BBCDC, A, B, C, D, E )
#define R4(_block, _ws, _t, A, B, C, D, E)   SHA_ROUND(_block, _ws, _t, SHA_MIX, (B^C^D) ,  0xCA62C1D6, A, B, C, D, E )

static inline uint32_t mix_value(uint32_t* ws, uint32_t t)
{
    uint32_t val = SHA_WS(ws, t+13) ^ SHA_WS(ws, t+8) ^ SHA_WS(ws, t+2) ^ SHA_WS(ws, t);
    return SHA_ROL(val, 1);
}

static void crypto_sha1_block_update(crypto_sha1_t *self, const uint8_t* data)
{
 	uint32_t array[16];

 	uint32_t A = self->state[0];
 	uint32_t B = self->state[1];
 	uint32_t C = self->state[2];
 	uint32_t D = self->state[3];
 	uint32_t E = self->state[4];

 	// Round 1 - iterations 0-16 take their input from 'block' 
    if (self->little_endian)
    {
        RLE(data, array,  0, A, B, C, D, E);    RLE(data, array,  1, E, A, B, C, D);
        RLE(data, array,  2, D, E, A, B, C);    RLE(data, array,  3, C, D, E, A, B);
        RLE(data, array,  4, B, C, D, E, A);    RLE(data, array,  5, A, B, C, D, E);
        RLE(data, array,  6, E, A, B, C, D);    RLE(data, array,  7, D, E, A, B, C);
        RLE(data, array,  8, C, D, E, A, B);    RLE(data, array,  9, B, C, D, E, A);
        RLE(data, array, 10, A, B, C, D, E);    RLE(data, array, 11, E, A, B, C, D);
        RLE(data, array, 12, D, E, A, B, C);    RLE(data, array, 13, C, D, E, A, B);
        RLE(data, array, 14, B, C, D, E, A);    RLE(data, array, 15, A, B, C, D, E);
    }
    else
    {
        RBE(data, array,  0, A, B, C, D, E);    RBE(data, array,  1, E, A, B, C, D);
        RBE(data, array,  2, D, E, A, B, C);    RBE(data, array,  3, C, D, E, A, B);
        RBE(data, array,  4, B, C, D, E, A);    RBE(data, array,  5, A, B, C, D, E);
        RBE(data, array,  6, E, A, B, C, D);    RBE(data, array,  7, D, E, A, B, C);
        RBE(data, array,  8, C, D, E, A, B);    RBE(data, array,  9, B, C, D, E, A);
        RBE(data, array, 10, A, B, C, D, E);    RBE(data, array, 11, E, A, B, C, D);
        RBE(data, array, 12, D, E, A, B, C);    RBE(data, array, 13, C, D, E, A, B);
        RBE(data, array, 14, B, C, D, E, A);    RBE(data, array, 15, A, B, C, D, E);
    }

 	// Round 1 - tail. Input from 512-bit mixing array 
 	R1(data, array, 16, E, A, B, C, D);
 	R1(data, array, 17, D, E, A, B, C);
 	R1(data, array, 18, C, D, E, A, B);
 	R1(data, array, 19, B, C, D, E, A);
 	//Round 2 
	R2(data, array, 20, A, B, C, D, E); R2(data, array, 21, E, A, B, C, D);
	R2(data, array, 22, D, E, A, B, C);	R2(data, array, 23, C, D, E, A, B);
	R2(data, array, 24, B, C, D, E, A);	R2(data, array, 25, A, B, C, D, E);
	R2(data, array, 26, E, A, B, C, D);	R2(data, array, 27, D, E, A, B, C);
	R2(data, array, 28, C, D, E, A, B);	R2(data, array, 29, B, C, D, E, A);
	R2(data, array, 30, A, B, C, D, E);	R2(data, array, 31, E, A, B, C, D);
	R2(data, array, 32, D, E, A, B, C);	R2(data, array, 33, C, D, E, A, B);
	R2(data, array, 34, B, C, D, E, A);	R2(data, array, 35, A, B, C, D, E);
	R2(data, array, 36, E, A, B, C, D);	R2(data, array, 37, D, E, A, B, C);
	R2(data, array, 38, C, D, E, A, B);	R2(data, array, 39, B, C, D, E, A);
 	// Round 3 
	R3(data, array, 40, A, B, C, D, E);	R3(data, array, 41, E, A, B, C, D);
	R3(data, array, 42, D, E, A, B, C);	R3(data, array, 43, C, D, E, A, B);
	R3(data, array, 44, B, C, D, E, A);	R3(data, array, 45, A, B, C, D, E);
	R3(data, array, 46, E, A, B, C, D);	R3(data, array, 47, D, E, A, B, C);
	R3(data, array, 48, C, D, E, A, B);	R3(data, array, 49, B, C, D, E, A);
	R3(data, array, 50, A, B, C, D, E);	R3(data, array, 51, E, A, B, C, D);
	R3(data, array, 52, D, E, A, B, C);	R3(data, array, 53, C, D, E, A, B);
	R3(data, array, 54, B, C, D, E, A);	R3(data, array, 55, A, B, C, D, E);
	R3(data, array, 56, E, A, B, C, D);	R3(data, array, 57, D, E, A, B, C);
	R3(data, array, 58, C, D, E, A, B);	R3(data, array, 59, B, C, D, E, A);
	// Round 4 
	R4(data, array, 60, A, B, C, D, E);	R4(data, array, 61, E, A, B, C, D);
	R4(data, array, 62, D, E, A, B, C);	R4(data, array, 63, C, D, E, A, B);
	R4(data, array, 64, B, C, D, E, A);	R4(data, array, 65, A, B, C, D, E);
	R4(data, array, 66, E, A, B, C, D);	R4(data, array, 67, D, E, A, B, C);
	R4(data, array, 68, C, D, E, A, B);	R4(data, array, 69, B, C, D, E, A);
	R4(data, array, 70, A, B, C, D, E);	R4(data, array, 71, E, A, B, C, D);
	R4(data, array, 72, D, E, A, B, C);	R4(data, array, 73, C, D, E, A, B);
	R4(data, array, 74, B, C, D, E, A);	R4(data, array, 75, A, B, C, D, E);
	R4(data, array, 76, E, A, B, C, D);	R4(data, array, 77, D, E, A, B, C);
	R4(data, array, 78, C, D, E, A, B);	R4(data, array, 79, B, C, D, E, A);

	self->state[0] += A;
	self->state[1] += B;
	self->state[2] += C;
	self->state[3] += D;
	self->state[4] += E;
}

void crypto_sha1_init(crypto_sha1_t *self)
{
    self->state[0] = 0x67452301;
    self->state[1] = 0xEFCDAB89;
    self->state[2] = 0x98BADCFE;
    self->state[3] = 0x10325476;
    self->state[4] = 0xC3D2E1F0;
    self->size = 0;
    self->little_endian = basic_byte_order_is_little();
}


void crypto_sha1_update(crypto_sha1_t *self, const uint8_t* data, size_t len)
{
    uint32_t used = self->size & 63;
    self->size += len;

    if (used)
    {
        size_t left = MIN(64-used, len);
 		memcpy(self->buffer + used, data, left);

        used = (used + left) & 63;
 		len -= left;
        data += left;
        if (used != 0) return;

 		crypto_sha1_block_update(self, self->buffer);
 	}

 	while (len >= 64) 
    {
        crypto_sha1_block_update(self, data);
        data += 64;
        len -= 64;
    }
 	if (len)
    {
        memcpy(self->buffer, data, len);        
    }
}

bool crypto_sha1_final(crypto_sha1_t *self, uint8_t* result, size_t size)
{
    if (size < DSIZE_SHA1_RESULT) return false;

    const uint8_t pad[64] = { 0x80 };
    uint32_t padlen[2];

 	padlen[0] = basic_byte_h2be_32((uint32_t)(self->size >> 29));
 	padlen[1] = basic_byte_h2be_32((uint32_t)(self->size << 3));

    uint32_t remain = (uint32_t) (self->size & 63);
    crypto_sha1_update(self, pad, 1 + (63 & (55 - remain)));
    crypto_sha1_update(self, (uint8_t*) padlen, 8);

    uint32_t *ret = (uint32_t *) result;
    for(size_t i=0; i<5; i++) ret[i] = basic_byte_h2be_32(self->state[i]);
    return true;
}

