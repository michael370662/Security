#include <PonyTech-LowLevel-Crypto/crypto.h>
#include "../PonyTech-LowLevel-Crypto_DEP.h"

//http://loup-vaillant.fr/tutorials/chacha20-design

#define CHACHA20_QUARTERROUND(_x, _a, _b, _c, _d) \
    _x[(_a)] += _x[(_b)]; _x[(_d)] = rotl32(_x[(_d)] ^ _x[(_a)], 16); \
    _x[(_c)] += _x[(_d)]; _x[(_b)] = rotl32(_x[(_b)] ^ _x[(_c)], 12); \
    _x[(_a)] += _x[(_b)]; _x[(_d)] = rotl32(_x[(_d)] ^ _x[(_a)], 8); \
    _x[(_c)] += _x[(_d)]; _x[(_b)] = rotl32(_x[(_b)] ^ _x[(_c)], 7);


static uint32_t rotl32(uint32_t x, int n) 
{
	return (x << n) | (x >> (32 - n));
}

static void chacha20_block_next(struct crypto_chacha20_t *self) {
	// This is where the crazy voodoo magic happens.
	// Mix the result a lot and hope that nobody finds out how to undo it.
	for (int i = 0; i < 16; i++) self->keystream32[i] = self->state[i];



	for (int i = 0; i < 10; i++) 
	{
		CHACHA20_QUARTERROUND(self->keystream32, 0, 4, 8, 12)
		CHACHA20_QUARTERROUND(self->keystream32, 1, 5, 9, 13)
		CHACHA20_QUARTERROUND(self->keystream32, 2, 6, 10, 14)
		CHACHA20_QUARTERROUND(self->keystream32, 3, 7, 11, 15)
		CHACHA20_QUARTERROUND(self->keystream32, 0, 5, 10, 15)
		CHACHA20_QUARTERROUND(self->keystream32, 1, 6, 11, 12)
		CHACHA20_QUARTERROUND(self->keystream32, 2, 7, 8, 13)
		CHACHA20_QUARTERROUND(self->keystream32, 3, 4, 9, 14)
	}

	for (int i = 0; i < 16; i++) self->keystream32[i] += self->state[i];

	// increment size
	self->state[12]++;
	if (0 == self->state[12]) 
	{
		// wrap around occured, increment higher 32 bits of size
		self->state[13]++;
	}
}

void crypto_chacha20_init(struct crypto_chacha20_t *self, uint8_t* key, uint64_t nonce)
{
	const uint8_t *magic_constant = (uint8_t*)"expand 32-byte k";
	self->state[0 ] = basic_byte_be2h_32(*((uint32_t*) (magic_constant + 0 * 4)));
	self->state[1 ] = basic_byte_be2h_32(*((uint32_t*) (magic_constant + 1 * 4)));
	self->state[2 ] = basic_byte_be2h_32(*((uint32_t*) (magic_constant + 2 * 4)));
	self->state[3 ] = basic_byte_be2h_32(*((uint32_t*) (magic_constant + 3 * 4)));
	self->state[4 ] = basic_byte_be2h_32(*((uint32_t*) (key + 0 * 4)));
	self->state[5 ] = basic_byte_be2h_32(*((uint32_t*) (key + 1 * 4)));
	self->state[6 ] = basic_byte_be2h_32(*((uint32_t*) (key + 2 * 4)));
	self->state[7 ] = basic_byte_be2h_32(*((uint32_t*) (key + 3 * 4)));
	self->state[8 ] = basic_byte_be2h_32(*((uint32_t*) (key + 4 * 4)));
	self->state[9 ] = basic_byte_be2h_32(*((uint32_t*) (key + 5 * 4)));
	self->state[10] = basic_byte_be2h_32(*((uint32_t*) (key + 6 * 4)));
	self->state[11] = basic_byte_be2h_32(*((uint32_t*) (key + 7 * 4)));
	self->state[12] = 0;
	self->state[13] = 0;
	self->state[14] = nonce >> 32;
	self->state[15] = (uint32_t) nonce ;
}

void crypto_chacha20_crypto(struct crypto_chacha20_t *self, const uint8_t *input, uint8_t *output, size_t size)
{
	size_t block = size / 64;
	for(size_t i=0; i<block; i++)
	{
		chacha20_block_next(self);
		// block encryption
		for(size_t j=0; j<16; j++)
		{
			uint32_t result = basic_byte_h2be_32(self->keystream32[j]) ^ *((uint32_t*) (input + j * 4));
			*((uint32_t*) (output + j * 4)) = result;
		}
		input += 64;		
		output += 64;
	}

	size_t remain = size & 0x3f;
	if (remain == 0) return;

	chacha20_block_next(self);

	// process remain item of 4
	size_t item_of_4 = remain / 4;
	for(size_t i=0; i<item_of_4; i++) 
	{
		uint32_t result = basic_byte_h2be_32(self->keystream32[i]) ^ *((uint32_t*) (input + i * 4));
		*((uint32_t*) (output + i * 4)) = result;
	}
	input += item_of_4 * 4;		
	output += item_of_4 * 4;	

	// process remain not up to 4
	uint32_t key = basic_byte_h2be_32(self->keystream32[item_of_4]);
	uint8_t *key_pos = (uint8_t*) &key;

	for(size_t i=0; i < (remain & 3); i++) 
	{
		*(output++) = *(input++) ^ key_pos[i];
	}
}