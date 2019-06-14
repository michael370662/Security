//  https://github.com/ogay/sha2

#include <PonyTech-LowLevel-Crypto/hasher.h>
#include "../PonyTech-LowLevel-Crypto_DEP.h"

#define SHA224_DIGEST_SIZE ( 224 / 8)
#define SHA256_DIGEST_SIZE ( 256 / 8)
#define SHA384_DIGEST_SIZE ( 384 / 8)
#define SHA512_DIGEST_SIZE ( 512 / 8)

#define SHA256_BLOCK_SIZE  ( 512 / 8)
#define SHA512_BLOCK_SIZE  (1024 / 8)
#define SHA384_BLOCK_SIZE  SHA512_BLOCK_SIZE
#define SHA224_BLOCK_SIZE  SHA256_BLOCK_SIZE

#define SHFR(_x, _n)    ((_x) >> (_n))
#define ROTR(_x, _n)   (((_x) >> (_n)) | ((_x) << ((sizeof(_x) << 3) - (_n))))
#define ROTL(_x, _n)   (((_x) << (_n)) | ((_x) >> ((sizeof(_x) << 3) - (_n))))
#define CH(_x, _y, _z)  (((_x) & (_y)) ^ (~(_x) & (_z)))
#define MAJ(_x, _y, _z) (((_x) & (_y)) ^ ((_x) & (_z)) ^ ((_y) & (_z)))

#define SHA256_F1(_x) (ROTR((_x),  2) ^ ROTR((_x), 13) ^ ROTR((_x), 22))
#define SHA256_F2(_x) (ROTR((_x),  6) ^ ROTR((_x), 11) ^ ROTR((_x), 25))
#define SHA256_F3(_x) (ROTR((_x),  7) ^ ROTR((_x), 18) ^ SHFR((_x),  3))
#define SHA256_F4(_x) (ROTR((_x), 17) ^ ROTR((_x), 19) ^ SHFR((_x), 10))

#define SHA512_F1(_x) (ROTR((_x), 28) ^ ROTR((_x), 34) ^ ROTR((_x), 39))
#define SHA512_F2(_x) (ROTR((_x), 14) ^ ROTR((_x), 18) ^ ROTR((_x), 41))
#define SHA512_F3(_x) (ROTR((_x),  1) ^ ROTR((_x),  8) ^ SHFR((_x),  7))
#define SHA512_F4(_x) (ROTR((_x), 19) ^ ROTR((_x), 61) ^ SHFR((_x),  6))

// Macros used for loops unrolling 

#define SHA256_SCR(_i)                                \
{                                                     \
    w[(_i)] =  SHA256_F4(w[(_i) -  2]) + w[(_i) -  7] \
          + SHA256_F3(w[(_i) - 15]) + w[(_i) - 16];   \
}

#define SHA512_SCR(_i)                                 \
{                                                      \
    w[(_i)] =  SHA512_F4(w[(_i) -  2]) + w[(_i) -  7]  \
          + SHA512_F3(w[(_i) - 15]) + w[(_i) - 16];    \
}

#define SHA256_EXP(_a, _b, _c, _d, _e, _f, _g, _h, _j)                     \
{                                                                          \
    t1 = wv[(_h)] + SHA256_F2(wv[(_e)]) + CH(wv[(_e)], wv[(_f)], wv[(_g)]) \
         + sha256_k[(_j)] + w[(_j)];                                       \
    t2 = SHA256_F1(wv[(_a)]) + MAJ(wv[(_a)], wv[(_b)], wv[(_c)]);          \
    wv[(_d)] += t1;                                                        \
    wv[(_h)] = t1 + t2;                                                    \
}

#define SHA512_EXP(_a, _b, _c, _d, _e, _f, _g ,_h, _j)                      \
{                                                                           \
    t1 = wv[(_h)] + SHA512_F2(wv[(_e)]) + CH(wv[(_e)], wv[(_f)], wv[(_g)])  \
         + sha512_k[(_j)] + w[(_j)];                                        \
    t2 = SHA512_F1(wv[(_a)]) + MAJ(wv[(_a)], wv[(_b)], wv[(_c)]);           \
    wv[(_d)] += t1;                                                         \
    wv[(_h)] = t1 + t2;                                                     \
}

uint32_t sha224_h0[8] =
            {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
             0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};

uint32_t sha256_h0[8] =
            {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

uint64_t sha384_h0[8] =
            {0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
             0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
             0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
             0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};

uint64_t sha512_h0[8] =
            {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
             0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
             0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
             0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

uint32_t sha256_k[64] =
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

uint64_t sha512_k[80] =
            {0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
             0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
             0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
             0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
             0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
             0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
             0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
             0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
             0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
             0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
             0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
             0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
             0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
             0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
             0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
             0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
             0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
             0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
             0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
             0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
             0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
             0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
             0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
             0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
             0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
             0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
             0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
             0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
             0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
             0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
             0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
             0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
             0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
             0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
             0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
             0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
             0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
             0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
             0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
             0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

// SHA-256 functions 

static void sha256_transform(crypto_sha2_t *self, const uint8_t *message,
                   size_t block_nb)
{
    uint32_t w[64];
    uint32_t wv[8];
    uint32_t t1, t2;
    const uint8_t *sub_block;
    
    for (int i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);

        *((uint32_t*) w + 0) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 0 * 4)));
        *((uint32_t*) w + 1) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 1 * 4)));
        *((uint32_t*) w + 2) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 2 * 4)));
        *((uint32_t*) w + 3) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 3 * 4)));
        *((uint32_t*) w + 4) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 4 * 4)));
        *((uint32_t*) w + 5) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 5 * 4)));
        *((uint32_t*) w + 6) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 6 * 4)));
        *((uint32_t*) w + 7) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 7 * 4)));
        *((uint32_t*) w + 8) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 8 * 4)));
        *((uint32_t*) w + 9) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 9 * 4)));
        *((uint32_t*) w + 10) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 10 * 4)));
        *((uint32_t*) w + 11) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 11 * 4)));
        *((uint32_t*) w + 12) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 12 * 4)));
        *((uint32_t*) w + 13) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 13 * 4)));
        *((uint32_t*) w + 14) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 14 * 4)));
        *((uint32_t*) w + 15) = basic_byte_be2h_32(*((uint32_t*) (sub_block + 15 * 4)));

        SHA256_SCR(16); SHA256_SCR(17); SHA256_SCR(18); SHA256_SCR(19);
        SHA256_SCR(20); SHA256_SCR(21); SHA256_SCR(22); SHA256_SCR(23);
        SHA256_SCR(24); SHA256_SCR(25); SHA256_SCR(26); SHA256_SCR(27);
        SHA256_SCR(28); SHA256_SCR(29); SHA256_SCR(30); SHA256_SCR(31);
        SHA256_SCR(32); SHA256_SCR(33); SHA256_SCR(34); SHA256_SCR(35);
        SHA256_SCR(36); SHA256_SCR(37); SHA256_SCR(38); SHA256_SCR(39);
        SHA256_SCR(40); SHA256_SCR(41); SHA256_SCR(42); SHA256_SCR(43);
        SHA256_SCR(44); SHA256_SCR(45); SHA256_SCR(46); SHA256_SCR(47);
        SHA256_SCR(48); SHA256_SCR(49); SHA256_SCR(50); SHA256_SCR(51);
        SHA256_SCR(52); SHA256_SCR(53); SHA256_SCR(54); SHA256_SCR(55);
        SHA256_SCR(56); SHA256_SCR(57); SHA256_SCR(58); SHA256_SCR(59);
        SHA256_SCR(60); SHA256_SCR(61); SHA256_SCR(62); SHA256_SCR(63);

        wv[0] = self->h.h32[0]; wv[1] = self->h.h32[1];
        wv[2] = self->h.h32[2]; wv[3] = self->h.h32[3];
        wv[4] = self->h.h32[4]; wv[5] = self->h.h32[5];
        wv[6] = self->h.h32[6]; wv[7] = self->h.h32[7];

        SHA256_EXP(0,1,2,3,4,5,6,7, 0); SHA256_EXP(7,0,1,2,3,4,5,6, 1);
        SHA256_EXP(6,7,0,1,2,3,4,5, 2); SHA256_EXP(5,6,7,0,1,2,3,4, 3);
        SHA256_EXP(4,5,6,7,0,1,2,3, 4); SHA256_EXP(3,4,5,6,7,0,1,2, 5);
        SHA256_EXP(2,3,4,5,6,7,0,1, 6); SHA256_EXP(1,2,3,4,5,6,7,0, 7);
        SHA256_EXP(0,1,2,3,4,5,6,7, 8); SHA256_EXP(7,0,1,2,3,4,5,6, 9);
        SHA256_EXP(6,7,0,1,2,3,4,5,10); SHA256_EXP(5,6,7,0,1,2,3,4,11);
        SHA256_EXP(4,5,6,7,0,1,2,3,12); SHA256_EXP(3,4,5,6,7,0,1,2,13);
        SHA256_EXP(2,3,4,5,6,7,0,1,14); SHA256_EXP(1,2,3,4,5,6,7,0,15);
        SHA256_EXP(0,1,2,3,4,5,6,7,16); SHA256_EXP(7,0,1,2,3,4,5,6,17);
        SHA256_EXP(6,7,0,1,2,3,4,5,18); SHA256_EXP(5,6,7,0,1,2,3,4,19);
        SHA256_EXP(4,5,6,7,0,1,2,3,20); SHA256_EXP(3,4,5,6,7,0,1,2,21);
        SHA256_EXP(2,3,4,5,6,7,0,1,22); SHA256_EXP(1,2,3,4,5,6,7,0,23);
        SHA256_EXP(0,1,2,3,4,5,6,7,24); SHA256_EXP(7,0,1,2,3,4,5,6,25);
        SHA256_EXP(6,7,0,1,2,3,4,5,26); SHA256_EXP(5,6,7,0,1,2,3,4,27);
        SHA256_EXP(4,5,6,7,0,1,2,3,28); SHA256_EXP(3,4,5,6,7,0,1,2,29);
        SHA256_EXP(2,3,4,5,6,7,0,1,30); SHA256_EXP(1,2,3,4,5,6,7,0,31);
        SHA256_EXP(0,1,2,3,4,5,6,7,32); SHA256_EXP(7,0,1,2,3,4,5,6,33);
        SHA256_EXP(6,7,0,1,2,3,4,5,34); SHA256_EXP(5,6,7,0,1,2,3,4,35);
        SHA256_EXP(4,5,6,7,0,1,2,3,36); SHA256_EXP(3,4,5,6,7,0,1,2,37);
        SHA256_EXP(2,3,4,5,6,7,0,1,38); SHA256_EXP(1,2,3,4,5,6,7,0,39);
        SHA256_EXP(0,1,2,3,4,5,6,7,40); SHA256_EXP(7,0,1,2,3,4,5,6,41);
        SHA256_EXP(6,7,0,1,2,3,4,5,42); SHA256_EXP(5,6,7,0,1,2,3,4,43);
        SHA256_EXP(4,5,6,7,0,1,2,3,44); SHA256_EXP(3,4,5,6,7,0,1,2,45);
        SHA256_EXP(2,3,4,5,6,7,0,1,46); SHA256_EXP(1,2,3,4,5,6,7,0,47);
        SHA256_EXP(0,1,2,3,4,5,6,7,48); SHA256_EXP(7,0,1,2,3,4,5,6,49);
        SHA256_EXP(6,7,0,1,2,3,4,5,50); SHA256_EXP(5,6,7,0,1,2,3,4,51);
        SHA256_EXP(4,5,6,7,0,1,2,3,52); SHA256_EXP(3,4,5,6,7,0,1,2,53);
        SHA256_EXP(2,3,4,5,6,7,0,1,54); SHA256_EXP(1,2,3,4,5,6,7,0,55);
        SHA256_EXP(0,1,2,3,4,5,6,7,56); SHA256_EXP(7,0,1,2,3,4,5,6,57);
        SHA256_EXP(6,7,0,1,2,3,4,5,58); SHA256_EXP(5,6,7,0,1,2,3,4,59);
        SHA256_EXP(4,5,6,7,0,1,2,3,60); SHA256_EXP(3,4,5,6,7,0,1,2,61);
        SHA256_EXP(2,3,4,5,6,7,0,1,62); SHA256_EXP(1,2,3,4,5,6,7,0,63);

        self->h.h32[0] += wv[0]; self->h.h32[1] += wv[1];
        self->h.h32[2] += wv[2]; self->h.h32[3] += wv[3];
        self->h.h32[4] += wv[4]; self->h.h32[5] += wv[5];
        self->h.h32[6] += wv[6]; self->h.h32[7] += wv[7];
    }
}

void crypto_sha256_init(crypto_sha2_t *self)
{

    self->h.h32[0] = sha256_h0[0]; self->h.h32[1] = sha256_h0[1];
    self->h.h32[2] = sha256_h0[2]; self->h.h32[3] = sha256_h0[3];
    self->h.h32[4] = sha256_h0[4]; self->h.h32[5] = sha256_h0[5];
    self->h.h32[6] = sha256_h0[6]; self->h.h32[7] = sha256_h0[7];

    self->len = 0;
    self->tot_len = 0;
}

void crypto_sha256_update(crypto_sha2_t *self, const uint8_t *message,
                   size_t len)
{
    uint32_t new_len, rem_len, tmp_len;

    tmp_len = SHA256_BLOCK_SIZE - self->len;
    rem_len = MIN(len, tmp_len);

    memcpy(self->block + self->len, message, rem_len);

    if (self->len + len < SHA256_BLOCK_SIZE) {
        self->len += len;
        return;
    }

    new_len = len - rem_len;
    size_t block_nb = new_len / SHA256_BLOCK_SIZE;

    const uint8_t *shifted_message = message + rem_len;

    sha256_transform(self, self->block, 1);
    sha256_transform(self, shifted_message, block_nb);

    rem_len = new_len % SHA256_BLOCK_SIZE;

    memcpy(self->block, shifted_message + (block_nb << 6), rem_len); // This is the logic that prevented corrupting after the blk. 


    self->len = rem_len;
    self->tot_len += (block_nb + 1) << 6;
}

void crypto_sha256_final(crypto_sha2_t *self, uint8_t *digest)
{   
    uint32_t pm_len;
    uint32_t len_b;

    size_t block_nb = ((SHA256_BLOCK_SIZE - 9) < (self->len % SHA256_BLOCK_SIZE) ? 1 : 0) + 1;


    len_b = (self->tot_len + self->len) << 3;
    pm_len = block_nb << 6;

    memset(self->block + self->len, 0, pm_len - self->len);
    self->block[self->len] = 0x80;
    *((uint32_t*) (self->block + pm_len - 4)) = basic_byte_h2be_32(len_b);
    sha256_transform(self, self->block, block_nb);


   *((uint32_t*) (digest + 0)) = basic_byte_h2be_32(self->h.h32[0]);
   *((uint32_t*) (digest + 1 * 4)) = basic_byte_h2be_32(self->h.h32[1]);
   *((uint32_t*) (digest + 2 * 4)) = basic_byte_h2be_32(self->h.h32[2]);
   *((uint32_t*) (digest + 3 * 4)) = basic_byte_h2be_32(self->h.h32[3]);
   *((uint32_t*) (digest + 4 * 4)) = basic_byte_h2be_32(self->h.h32[4]);
   *((uint32_t*) (digest + 5 * 4)) = basic_byte_h2be_32(self->h.h32[5]);
   *((uint32_t*) (digest + 6 * 4)) = basic_byte_h2be_32(self->h.h32[6]);
   *((uint32_t*) (digest + 7 * 4)) = basic_byte_h2be_32(self->h.h32[7]);

}

// SHA-512 functions 

static void sha512_transform(crypto_sha2_t *self, const uint8_t *message,
                   size_t block_nb)
{
    uint64_t w[80];
    uint64_t wv[8];
    uint64_t t1, t2;
    const uint8_t *sub_block;

    for (int i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 7);

        *((uint64_t*) w + 0) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 0 * 8)));
        *((uint64_t*) w + 1) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 1 * 8)));
        *((uint64_t*) w + 2) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 2 * 8)));
        *((uint64_t*) w + 3) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 3 * 8)));
        *((uint64_t*) w + 4) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 4 * 8)));
        *((uint64_t*) w + 5) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 5 * 8)));
        *((uint64_t*) w + 6) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 6 * 8)));
        *((uint64_t*) w + 7) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 7 * 8)));
        *((uint64_t*) w + 8) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 8 * 8)));
        *((uint64_t*) w + 9) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 9 * 8)));
        *((uint64_t*) w + 10) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 10 * 8)));
        *((uint64_t*) w + 11) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 11 * 8)));
        *((uint64_t*) w + 12) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 12 * 8)));
        *((uint64_t*) w + 13) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 13 * 8)));
        *((uint64_t*) w + 14) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 14 * 8)));
        *((uint64_t*) w + 15) = basic_byte_be2h_64(*((uint64_t*) (sub_block + 15 * 8)));

        SHA512_SCR(16); SHA512_SCR(17); SHA512_SCR(18); SHA512_SCR(19);
        SHA512_SCR(20); SHA512_SCR(21); SHA512_SCR(22); SHA512_SCR(23);
        SHA512_SCR(24); SHA512_SCR(25); SHA512_SCR(26); SHA512_SCR(27);
        SHA512_SCR(28); SHA512_SCR(29); SHA512_SCR(30); SHA512_SCR(31);
        SHA512_SCR(32); SHA512_SCR(33); SHA512_SCR(34); SHA512_SCR(35);
        SHA512_SCR(36); SHA512_SCR(37); SHA512_SCR(38); SHA512_SCR(39);
        SHA512_SCR(40); SHA512_SCR(41); SHA512_SCR(42); SHA512_SCR(43);
        SHA512_SCR(44); SHA512_SCR(45); SHA512_SCR(46); SHA512_SCR(47);
        SHA512_SCR(48); SHA512_SCR(49); SHA512_SCR(50); SHA512_SCR(51);
        SHA512_SCR(52); SHA512_SCR(53); SHA512_SCR(54); SHA512_SCR(55);
        SHA512_SCR(56); SHA512_SCR(57); SHA512_SCR(58); SHA512_SCR(59);
        SHA512_SCR(60); SHA512_SCR(61); SHA512_SCR(62); SHA512_SCR(63);
        SHA512_SCR(64); SHA512_SCR(65); SHA512_SCR(66); SHA512_SCR(67);
        SHA512_SCR(68); SHA512_SCR(69); SHA512_SCR(70); SHA512_SCR(71);
        SHA512_SCR(72); SHA512_SCR(73); SHA512_SCR(74); SHA512_SCR(75);
        SHA512_SCR(76); SHA512_SCR(77); SHA512_SCR(78); SHA512_SCR(79);

        wv[0] = self->h.h64[0]; wv[1] = self->h.h64[1];
        wv[2] = self->h.h64[2]; wv[3] = self->h.h64[3];
        wv[4] = self->h.h64[4]; wv[5] = self->h.h64[5];
        wv[6] = self->h.h64[6]; wv[7] = self->h.h64[7];

        int j = 0;

        do {
            SHA512_EXP(0,1,2,3,4,5,6,7,j); j++;
            SHA512_EXP(7,0,1,2,3,4,5,6,j); j++;
            SHA512_EXP(6,7,0,1,2,3,4,5,j); j++;
            SHA512_EXP(5,6,7,0,1,2,3,4,j); j++;
            SHA512_EXP(4,5,6,7,0,1,2,3,j); j++;
            SHA512_EXP(3,4,5,6,7,0,1,2,j); j++;
            SHA512_EXP(2,3,4,5,6,7,0,1,j); j++;
            SHA512_EXP(1,2,3,4,5,6,7,0,j); j++;
        } while (j < 80);

        self->h.h64[0] += wv[0]; self->h.h64[1] += wv[1];
        self->h.h64[2] += wv[2]; self->h.h64[3] += wv[3];
        self->h.h64[4] += wv[4]; self->h.h64[5] += wv[5];
        self->h.h64[6] += wv[6]; self->h.h64[7] += wv[7];

    }
}

void crypto_sha512_init(crypto_sha2_t *self)
{

    self->h.h64[0] = sha512_h0[0]; self->h.h64[1] = sha512_h0[1];
    self->h.h64[2] = sha512_h0[2]; self->h.h64[3] = sha512_h0[3];
    self->h.h64[4] = sha512_h0[4]; self->h.h64[5] = sha512_h0[5];
    self->h.h64[6] = sha512_h0[6]; self->h.h64[7] = sha512_h0[7];
    self->len = 0;
    self->tot_len = 0;
}

void crypto_sha512_update(crypto_sha2_t *self, const uint8_t *message,
                   size_t len)
{
    uint32_t new_len, rem_len, tmp_len;

    tmp_len = SHA512_BLOCK_SIZE - self->len;
    rem_len = MIN(len, tmp_len);

    memcpy(&self->block[self->len], message, rem_len);

    if (self->len + len < SHA512_BLOCK_SIZE) {
        self->len += len;
        return;
    }

    new_len = len - rem_len;
    size_t block_nb = new_len / SHA512_BLOCK_SIZE;

    const uint8_t *shifted_message = message + rem_len;

    sha512_transform(self, self->block, 1);
    sha512_transform(self, shifted_message, block_nb);

    rem_len = new_len % SHA512_BLOCK_SIZE;

    memcpy(self->block, &shifted_message[block_nb << 7],
           rem_len);

    self->len = rem_len;
    self->tot_len += (block_nb + 1) << 7;
}

void crypto_sha512_final(crypto_sha2_t *self, uint8_t *digest)
{
    uint32_t pm_len;
    uint32_t len_b;

    size_t block_nb = ((SHA512_BLOCK_SIZE - 17) < (self->len % SHA512_BLOCK_SIZE) ? 1 : 0) + 1;

    len_b = (self->tot_len + self->len) << 3;
    pm_len = block_nb << 7;

    memset(self->block + self->len, 0, pm_len - self->len);
    self->block[self->len] = 0x80;
    *((uint32_t*) (self->block + pm_len - 4)) = basic_byte_h2be_32(len_b);

    sha512_transform(self, self->block, block_nb);

   *((uint64_t*) (digest + 0)) = basic_byte_h2be_64(self->h.h64[0]);
   *((uint64_t*) (digest + 1 * 8)) = basic_byte_h2be_64(self->h.h64[1]);
   *((uint64_t*) (digest + 2 * 8)) = basic_byte_h2be_64(self->h.h64[2]);
   *((uint64_t*) (digest + 3 * 8)) = basic_byte_h2be_64(self->h.h64[3]);
   *((uint64_t*) (digest + 4 * 8)) = basic_byte_h2be_64(self->h.h64[4]);
   *((uint64_t*) (digest + 5 * 8)) = basic_byte_h2be_64(self->h.h64[5]);
   *((uint64_t*) (digest + 6 * 8)) = basic_byte_h2be_64(self->h.h64[6]);
   *((uint64_t*) (digest + 7 * 8)) = basic_byte_h2be_64(self->h.h64[7]);

}

// SHA-384 functions 

void crypto_sha384_init(crypto_sha2_t *self)
{
    self->h.h64[0] = sha384_h0[0]; self->h.h64[1] = sha384_h0[1];
    self->h.h64[2] = sha384_h0[2]; self->h.h64[3] = sha384_h0[3];
    self->h.h64[4] = sha384_h0[4]; self->h.h64[5] = sha384_h0[5];
    self->h.h64[6] = sha384_h0[6]; self->h.h64[7] = sha384_h0[7];


    self->len = 0;
    self->tot_len = 0;
}

void crypto_sha384_update(crypto_sha2_t *self, const uint8_t *message,
                   size_t len)
{
    uint32_t new_len, rem_len, tmp_len;

    tmp_len = SHA384_BLOCK_SIZE - self->len;
    rem_len = MIN(len, tmp_len);

    memcpy(&self->block[self->len], message, rem_len);

    if (self->len + len < SHA384_BLOCK_SIZE) {
        self->len += len;
        return;
    }

    new_len = len - rem_len;
    size_t block_nb = new_len / SHA384_BLOCK_SIZE;

    const uint8_t *shifted_message = message + rem_len;

    sha512_transform(self, self->block, 1);
    sha512_transform(self, shifted_message, block_nb);

    rem_len = new_len % SHA384_BLOCK_SIZE;

    memcpy(self->block, &shifted_message[block_nb << 7],
           rem_len);

    self->len = rem_len;
    self->tot_len += (block_nb + 1) << 7;
}

void crypto_sha384_final(crypto_sha2_t *self, uint8_t *digest)
{
    uint32_t pm_len;
    uint32_t len_b;

    size_t block_nb = ((SHA384_BLOCK_SIZE - 17) < (self->len % SHA384_BLOCK_SIZE) ? 1 : 0) + 1;

    len_b = (self->tot_len + self->len) << 3;
    pm_len = block_nb << 7;

    memset(self->block + self->len, 0, pm_len - self->len);
    self->block[self->len] = 0x80;
    *((uint32_t*) (self->block + pm_len - 4)) = basic_byte_h2be_32(len_b);

    sha512_transform(self, self->block, block_nb);

   *((uint64_t*) (digest + 0)) = basic_byte_h2be_64(self->h.h64[0]);
   *((uint64_t*) (digest + 1 * 8)) = basic_byte_h2be_64(self->h.h64[1]);
   *((uint64_t*) (digest + 2 * 8)) = basic_byte_h2be_64(self->h.h64[2]);
   *((uint64_t*) (digest + 3 * 8)) = basic_byte_h2be_64(self->h.h64[3]);
   *((uint64_t*) (digest + 4 * 8)) = basic_byte_h2be_64(self->h.h64[4]);
   *((uint64_t*) (digest + 5 * 8)) = basic_byte_h2be_64(self->h.h64[5]);

}

// SHA-224 functions

void crypto_sha224_init(crypto_sha2_t *self)
{

    self->h.h32[0] = sha224_h0[0]; self->h.h32[1] = sha224_h0[1];
    self->h.h32[2] = sha224_h0[2]; self->h.h32[3] = sha224_h0[3];
    self->h.h32[4] = sha224_h0[4]; self->h.h32[5] = sha224_h0[5];
    self->h.h32[6] = sha224_h0[6]; self->h.h32[7] = sha224_h0[7];

    self->len = 0;
    self->tot_len = 0;
}

void crypto_sha224_update(crypto_sha2_t *self, const uint8_t *message,
                   size_t len)
{
    uint32_t new_len, rem_len, tmp_len;

    tmp_len = SHA224_BLOCK_SIZE - self->len;
    rem_len = MIN(len, tmp_len);

    memcpy(&self->block[self->len], message, rem_len);

    if (self->len + len < SHA224_BLOCK_SIZE) {
        self->len += len;
        return;
    }

    new_len = len - rem_len;
    size_t block_nb = new_len / SHA224_BLOCK_SIZE;

    const uint8_t *shifted_message = message + rem_len;

    sha256_transform(self, self->block, 1);
    sha256_transform(self, shifted_message, block_nb);

    rem_len = new_len % SHA224_BLOCK_SIZE;

    memcpy(self->block, &shifted_message[block_nb << 6],
           rem_len);

    self->len = rem_len;
    self->tot_len += (block_nb + 1) << 6;
}

void crypto_sha224_final(crypto_sha2_t *self, uint8_t *digest)
{
    uint32_t pm_len;
    uint32_t len_b;

    size_t block_nb = ((SHA224_BLOCK_SIZE - 9) < (self->len % SHA224_BLOCK_SIZE) ? 1 : 0) + 1;

    len_b = (self->tot_len + self->len) << 3;
    pm_len = block_nb << 6;

    memset(self->block + self->len, 0, pm_len - self->len);
    self->block[self->len] = 0x80;
    *((uint32_t*) (self->block + pm_len - 4)) = basic_byte_h2be_32(len_b);

    sha256_transform(self, self->block, block_nb);

   *((uint32_t*) (digest + 0)) = basic_byte_h2be_32(self->h.h32[0]);
   *((uint32_t*) (digest + 1 * 4)) = basic_byte_h2be_32(self->h.h32[1]);
   *((uint32_t*) (digest + 2 * 4)) = basic_byte_h2be_32(self->h.h32[2]);
   *((uint32_t*) (digest + 3 * 4)) = basic_byte_h2be_32(self->h.h32[3]);
   *((uint32_t*) (digest + 4 * 4)) = basic_byte_h2be_32(self->h.h32[4]);
   *((uint32_t*) (digest + 5 * 4)) = basic_byte_h2be_32(self->h.h32[5]);
   *((uint32_t*) (digest + 6 * 4)) = basic_byte_h2be_32(self->h.h32[6]);

}
