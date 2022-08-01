/* $Id: sha2big.c 216 2010-06-08 09:46:57Z tp $ */
/*
 * SHA-384 / SHA-512 implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "sph_sha2.h"

#if SPH_64

#define CH(X, Y, Z)    ((((Y) ^ (Z)) & (X)) ^ (Z))
#define MAJ(X, Y, Z)   (((X) & (Y)) | (((X) | (Y)) & (Z)))

#define ROTR64    SPH_ROTR64

#define BSG5_0(x)      (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define BSG5_1(x)      (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SSG5_0(x)      (ROTR64(x, 1) ^ ROTR64(x, 8) ^ SPH_T64((x) >> 7))
#define SSG5_1(x)      (ROTR64(x, 19) ^ ROTR64(x, 61) ^ SPH_T64((x) >> 6))

static const sph_u64 K512[80] = {
	SPH_C64(0x428A2F98D728AE22), SPH_C64(0x7137449123EF65CD),
	SPH_C64(0xB5C0FBCFEC4D3B2F), SPH_C64(0xE9B5DBA58189DBBC),
	SPH_C64(0x3956C25BF348B538), SPH_C64(0x59F111F1B605D019),
	SPH_C64(0x923F82A4AF194F9B), SPH_C64(0xAB1C5ED5DA6D8118),
	SPH_C64(0xD807AA98A3030242), SPH_C64(0x12835B0145706FBE),
	SPH_C64(0x243185BE4EE4B28C), SPH_C64(0x550C7DC3D5FFB4E2),
	SPH_C64(0x72BE5D74F27B896F), SPH_C64(0x80DEB1FE3B1696B1),
	SPH_C64(0x9BDC06A725C71235), SPH_C64(0xC19BF174CF692694),
	SPH_C64(0xE49B69C19EF14AD2), SPH_C64(0xEFBE4786384F25E3),
	SPH_C64(0x0FC19DC68B8CD5B5), SPH_C64(0x240CA1CC77AC9C65),
	SPH_C64(0x2DE92C6F592B0275), SPH_C64(0x4A7484AA6EA6E483),
	SPH_C64(0x5CB0A9DCBD41FBD4), SPH_C64(0x76F988DA831153B5),
	SPH_C64(0x983E5152EE66DFAB), SPH_C64(0xA831C66D2DB43210),
	SPH_C64(0xB00327C898FB213F), SPH_C64(0xBF597FC7BEEF0EE4),
	SPH_C64(0xC6E00BF33DA88FC2), SPH_C64(0xD5A79147930AA725),
	SPH_C64(0x06CA6351E003826F), SPH_C64(0x142929670A0E6E70),
	SPH_C64(0x27B70A8546D22FFC), SPH_C64(0x2E1B21385C26C926),
	SPH_C64(0x4D2C6DFC5AC42AED), SPH_C64(0x53380D139D95B3DF),
	SPH_C64(0x650A73548BAF63DE), SPH_C64(0x766A0ABB3C77B2A8),
	SPH_C64(0x81C2C92E47EDAEE6), SPH_C64(0x92722C851482353B),
	SPH_C64(0xA2BFE8A14CF10364), SPH_C64(0xA81A664BBC423001),
	SPH_C64(0xC24B8B70D0F89791), SPH_C64(0xC76C51A30654BE30),
	SPH_C64(0xD192E819D6EF5218), SPH_C64(0xD69906245565A910),
	SPH_C64(0xF40E35855771202A), SPH_C64(0x106AA07032BBD1B8),
	SPH_C64(0x19A4C116B8D2D0C8), SPH_C64(0x1E376C085141AB53),
	SPH_C64(0x2748774CDF8EEB99), SPH_C64(0x34B0BCB5E19B48A8),
	SPH_C64(0x391C0CB3C5C95A63), SPH_C64(0x4ED8AA4AE3418ACB),
	SPH_C64(0x5B9CCA4F7763E373), SPH_C64(0x682E6FF3D6B2B8A3),
	SPH_C64(0x748F82EE5DEFB2FC), SPH_C64(0x78A5636F43172F60),
	SPH_C64(0x84C87814A1F0AB72), SPH_C64(0x8CC702081A6439EC),
	SPH_C64(0x90BEFFFA23631E28), SPH_C64(0xA4506CEBDE82BDE9),
	SPH_C64(0xBEF9A3F7B2C67915), SPH_C64(0xC67178F2E372532B),
	SPH_C64(0xCA273ECEEA26619C), SPH_C64(0xD186B8C721C0C207),
	SPH_C64(0xEADA7DD6CDE0EB1E), SPH_C64(0xF57D4F7FEE6ED178),
	SPH_C64(0x06F067AA72176FBA), SPH_C64(0x0A637DC5A2C898A6),
	SPH_C64(0x113F9804BEF90DAE), SPH_C64(0x1B710B35131C471B),
	SPH_C64(0x28DB77F523047D84), SPH_C64(0x32CAAB7B40C72493),
	SPH_C64(0x3C9EBE0A15C9BEBC), SPH_C64(0x431D67C49C100D4C),
	SPH_C64(0x4CC5D4BECB3E42B6), SPH_C64(0x597F299CFC657E2A),
	SPH_C64(0x5FCB6FAB3AD6FAEC), SPH_C64(0x6C44198C4A475817)
};

static const sph_u64 H384[8] = {
	SPH_C64(0xCBBB9D5DC1059ED8), SPH_C64(0x629A292A367CD507),
	SPH_C64(0x9159015A3070DD17), SPH_C64(0x152FECD8F70E5939),
	SPH_C64(0x67332667FFC00B31), SPH_C64(0x8EB44A8768581511),
	SPH_C64(0xDB0C2E0D64F98FA7), SPH_C64(0x47B5481DBEFA4FA4)
};

static const sph_u64 H512[8] = {
	SPH_C64(0x6A09E667F3BCC908), SPH_C64(0xBB67AE8584CAA73B),
	SPH_C64(0x3C6EF372FE94F82B), SPH_C64(0xA54FF53A5F1D36F1),
	SPH_C64(0x510E527FADE682D1), SPH_C64(0x9B05688C2B3E6C1F),
	SPH_C64(0x1F83D9ABFB41BD6B), SPH_C64(0x5BE0CD19137E2179)
};

/*
 * This macro defines the body for a SHA-384 / SHA-512 compression function
 * implementation. The "in" parameter should evaluate, when applied to a
 * numerical input parameter from 0 to 15, to an expression which yields
 * the corresponding input block. The "r" parameter should evaluate to
 * an array or pointer expression designating the array of 8 words which
 * contains the input and output of the compression function.
 *
 * SHA-512 is hard for the compiler. If the loop is completely unrolled,
 * then the code will be quite huge (possibly more than 100 kB), and the
 * performance will be degraded due to cache misses on the code. We
 * unroll only eight steps, which avoids all needless copies when
 * 64-bit registers are swapped.
 */

#define SHA3_STEP(A, B, C, D, E, F, G, H, i)   do { \
		sph_u64 T1, T2; \
		T1 = SPH_T64(H + BSG5_1(E) + CH(E, F, G) + K512[i] + W[i]); \
		T2 = SPH_T64(BSG5_0(A) + MAJ(A, B, C)); \
		D = SPH_T64(D + T1); \
		H = SPH_T64(T1 + T2); \
	} while (0)

#define SHA3_ROUND_BODY(in, r)   do { \
		int i; \
		sph_u64 A, B, C, D, E, F, G, H; \
		sph_u64 W[80]; \
 \
 		for (i = 0; i < 16; i ++) \
			W[i] = in(i); \
		for (i = 16; i < 80; i ++) \
 			W[i] = SPH_T64(SSG5_1(W[i - 2]) + W[i - 7] \
				+ SSG5_0(W[i - 15]) + W[i - 16]); \
		A = (r)[0]; \
		B = (r)[1]; \
		C = (r)[2]; \
		D = (r)[3]; \
		E = (r)[4]; \
		F = (r)[5]; \
		G = (r)[6]; \
		H = (r)[7]; \
		for (i = 0; i < 80; i += 8) { \
			SHA3_STEP(A, B, C, D, E, F, G, H, i + 0); \
			SHA3_STEP(H, A, B, C, D, E, F, G, i + 1); \
			SHA3_STEP(G, H, A, B, C, D, E, F, i + 2); \
			SHA3_STEP(F, G, H, A, B, C, D, E, i + 3); \
			SHA3_STEP(E, F, G, H, A, B, C, D, i + 4); \
			SHA3_STEP(D, E, F, G, H, A, B, C, i + 5); \
			SHA3_STEP(C, D, E, F, G, H, A, B, i + 6); \
			SHA3_STEP(B, C, D, E, F, G, H, A, i + 7); \
		} \
		(r)[0] = SPH_T64((r)[0] + A); \
		(r)[1] = SPH_T64((r)[1] + B); \
		(r)[2] = SPH_T64((r)[2] + C); \
		(r)[3] = SPH_T64((r)[3] + D); \
		(r)[4] = SPH_T64((r)[4] + E); \
		(r)[5] = SPH_T64((r)[5] + F); \
		(r)[6] = SPH_T64((r)[6] + G); \
		(r)[7] = SPH_T64((r)[7] + H); \
	} while (0)

/*
 * One round of SHA-384 / SHA-512. The data must be aligned for 64-bit access.
 */
static void
sha3_round(const unsigned char *data, sph_u64 r[8])
{
#define SHA3_IN(x)   sph_dec64be_aligned(data + (8 * (x)))
	SHA3_ROUND_BODY(SHA3_IN, r);
#undef SHA3_IN
}

/* see sph_sha3.h */
void
sph_sha384_init(void *cc)
{
	sph_sha384_context *sc;

	sc = (sph_sha384_context *)cc;
	memcpy(sc->val, H384, sizeof H384);
	sc->count = 0;
}

/* see sph_sha3.h */
void
sph_sha512_init(void *cc)
{
	sph_sha512_context *sc;

	sc = (sph_sha384_context *)cc;
	memcpy(sc->val, H512, sizeof H512);
	sc->count = 0;
}

#define RFUN   sha3_round
#define HASH   sha384
#define BE64   1
#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_SHA2
#define SPH_SMALL_FOOTPRINT_SHA2   1
#endif

#define CH(X, Y, Z)    ((((Y) ^ (Z)) & (X)) ^ (Z))
#define MAJ(X, Y, Z)   (((Y) & (Z)) | (((Y) | (Z)) & (X)))

#define ROTR    SPH_ROTR32

#define BSG2_0(x)      (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSG2_1(x)      (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSG2_0(x)      (ROTR(x, 7) ^ ROTR(x, 18) ^ SPH_T32((x) >> 3))
#define SSG2_1(x)      (ROTR(x, 17) ^ ROTR(x, 19) ^ SPH_T32((x) >> 10))

static const sph_u32 H224[8] = {
	SPH_C32(0xC1059ED8), SPH_C32(0x367CD507), SPH_C32(0x3070DD17),
	SPH_C32(0xF70E5939), SPH_C32(0xFFC00B31), SPH_C32(0x68581511),
	SPH_C32(0x64F98FA7), SPH_C32(0xBEFA4FA4)
};

static const sph_u32 H256[8] = {
	SPH_C32(0x6A09E667), SPH_C32(0xBB67AE85), SPH_C32(0x3C6EF372),
	SPH_C32(0xA54FF53A), SPH_C32(0x510E527F), SPH_C32(0x9B05688C),
	SPH_C32(0x1F83D9AB), SPH_C32(0x5BE0CD19)
};

/*
 * The SHA2_ROUND_BODY defines the body for a SHA-224 / SHA-256
 * compression function implementation. The "in" parameter should
 * evaluate, when applied to a numerical input parameter from 0 to 15,
 * to an expression which yields the corresponding input block. The "r"
 * parameter should evaluate to an array or pointer expression
 * designating the array of 8 words which contains the input and output
 * of the compression function.
 */

#if SPH_SMALL_FOOTPRINT_SHA2

static const sph_u32 K[64] = {
	SPH_C32(0x428A2F98), SPH_C32(0x71374491),
	SPH_C32(0xB5C0FBCF), SPH_C32(0xE9B5DBA5),
	SPH_C32(0x3956C25B), SPH_C32(0x59F111F1),
	SPH_C32(0x923F82A4), SPH_C32(0xAB1C5ED5),
	SPH_C32(0xD807AA98), SPH_C32(0x12835B01),
	SPH_C32(0x243185BE), SPH_C32(0x550C7DC3),
	SPH_C32(0x72BE5D74), SPH_C32(0x80DEB1FE),
	SPH_C32(0x9BDC06A7), SPH_C32(0xC19BF174),
	SPH_C32(0xE49B69C1), SPH_C32(0xEFBE4786),
	SPH_C32(0x0FC19DC6), SPH_C32(0x240CA1CC),
	SPH_C32(0x2DE92C6F), SPH_C32(0x4A7484AA),
	SPH_C32(0x5CB0A9DC), SPH_C32(0x76F988DA),
	SPH_C32(0x983E5152), SPH_C32(0xA831C66D),
	SPH_C32(0xB00327C8), SPH_C32(0xBF597FC7),
	SPH_C32(0xC6E00BF3), SPH_C32(0xD5A79147),
	SPH_C32(0x06CA6351), SPH_C32(0x14292967),
	SPH_C32(0x27B70A85), SPH_C32(0x2E1B2138),
	SPH_C32(0x4D2C6DFC), SPH_C32(0x53380D13),
	SPH_C32(0x650A7354), SPH_C32(0x766A0ABB),
	SPH_C32(0x81C2C92E), SPH_C32(0x92722C85),
	SPH_C32(0xA2BFE8A1), SPH_C32(0xA81A664B),
	SPH_C32(0xC24B8B70), SPH_C32(0xC76C51A3),
	SPH_C32(0xD192E819), SPH_C32(0xD6990624),
	SPH_C32(0xF40E3585), SPH_C32(0x106AA070),
	SPH_C32(0x19A4C116), SPH_C32(0x1E376C08),
	SPH_C32(0x2748774C), SPH_C32(0x34B0BCB5),
	SPH_C32(0x391C0CB3), SPH_C32(0x4ED8AA4A),
	SPH_C32(0x5B9CCA4F), SPH_C32(0x682E6FF3),
	SPH_C32(0x748F82EE), SPH_C32(0x78A5636F),
	SPH_C32(0x84C87814), SPH_C32(0x8CC70208),
	SPH_C32(0x90BEFFFA), SPH_C32(0xA4506CEB),
	SPH_C32(0xBEF9A3F7), SPH_C32(0xC67178F2)
};

#define SHA2_MEXP1(in, pc)   do { \
		W[pc] = in(pc); \
	} while (0)

#define SHA2_MEXP2(in, pc)   do { \
		W[(pc) & 0x0F] = SPH_T32(SSG2_1(W[((pc) - 2) & 0x0F]) \
			+ W[((pc) - 7) & 0x0F] \
			+ SSG2_0(W[((pc) - 15) & 0x0F]) + W[(pc) & 0x0F]); \
	} while (0)

#define SHA2_STEPn(n, a, b, c, d, e, f, g, h, in, pc)   do { \
		sph_u32 t1, t2; \
		SHA2_MEXP ## n(in, pc); \
		t1 = SPH_T32(h + BSG2_1(e) + CH(e, f, g) \
			+ K[pcount + (pc)] + W[(pc) & 0x0F]); \
		t2 = SPH_T32(BSG2_0(a) + MAJ(a, b, c)); \
		d = SPH_T32(d + t1); \
		h = SPH_T32(t1 + t2); \
	} while (0)

#define SHA2_STEP1(a, b, c, d, e, f, g, h, in, pc) \
	SHA2_STEPn(1, a, b, c, d, e, f, g, h, in, pc)
#define SHA2_STEP2(a, b, c, d, e, f, g, h, in, pc) \
	SHA2_STEPn(2, a, b, c, d, e, f, g, h, in, pc)

#define SHA2_ROUND_BODY(in, r)   do { \
		sph_u32 A, B, C, D, E, F, G, H; \
		sph_u32 W[16]; \
		unsigned pcount; \
 \
		A = (r)[0]; \
		B = (r)[1]; \
		C = (r)[2]; \
		D = (r)[3]; \
		E = (r)[4]; \
		F = (r)[5]; \
		G = (r)[6]; \
		H = (r)[7]; \
		pcount = 0; \
		SHA2_STEP1(A, B, C, D, E, F, G, H, in,  0); \
		SHA2_STEP1(H, A, B, C, D, E, F, G, in,  1); \
		SHA2_STEP1(G, H, A, B, C, D, E, F, in,  2); \
		SHA2_STEP1(F, G, H, A, B, C, D, E, in,  3); \
		SHA2_STEP1(E, F, G, H, A, B, C, D, in,  4); \
		SHA2_STEP1(D, E, F, G, H, A, B, C, in,  5); \
		SHA2_STEP1(C, D, E, F, G, H, A, B, in,  6); \
		SHA2_STEP1(B, C, D, E, F, G, H, A, in,  7); \
		SHA2_STEP1(A, B, C, D, E, F, G, H, in,  8); \
		SHA2_STEP1(H, A, B, C, D, E, F, G, in,  9); \
		SHA2_STEP1(G, H, A, B, C, D, E, F, in, 10); \
		SHA2_STEP1(F, G, H, A, B, C, D, E, in, 11); \
		SHA2_STEP1(E, F, G, H, A, B, C, D, in, 12); \
		SHA2_STEP1(D, E, F, G, H, A, B, C, in, 13); \
		SHA2_STEP1(C, D, E, F, G, H, A, B, in, 14); \
		SHA2_STEP1(B, C, D, E, F, G, H, A, in, 15); \
		for (pcount = 16; pcount < 64; pcount += 16) { \
			SHA2_STEP2(A, B, C, D, E, F, G, H, in,  0); \
			SHA2_STEP2(H, A, B, C, D, E, F, G, in,  1); \
			SHA2_STEP2(G, H, A, B, C, D, E, F, in,  2); \
			SHA2_STEP2(F, G, H, A, B, C, D, E, in,  3); \
			SHA2_STEP2(E, F, G, H, A, B, C, D, in,  4); \
			SHA2_STEP2(D, E, F, G, H, A, B, C, in,  5); \
			SHA2_STEP2(C, D, E, F, G, H, A, B, in,  6); \
			SHA2_STEP2(B, C, D, E, F, G, H, A, in,  7); \
			SHA2_STEP2(A, B, C, D, E, F, G, H, in,  8); \
			SHA2_STEP2(H, A, B, C, D, E, F, G, in,  9); \
			SHA2_STEP2(G, H, A, B, C, D, E, F, in, 10); \
			SHA2_STEP2(F, G, H, A, B, C, D, E, in, 11); \
			SHA2_STEP2(E, F, G, H, A, B, C, D, in, 12); \
			SHA2_STEP2(D, E, F, G, H, A, B, C, in, 13); \
			SHA2_STEP2(C, D, E, F, G, H, A, B, in, 14); \
			SHA2_STEP2(B, C, D, E, F, G, H, A, in, 15); \
		} \
		(r)[0] = SPH_T32((r)[0] + A); \
		(r)[1] = SPH_T32((r)[1] + B); \
		(r)[2] = SPH_T32((r)[2] + C); \
		(r)[3] = SPH_T32((r)[3] + D); \
		(r)[4] = SPH_T32((r)[4] + E); \
		(r)[5] = SPH_T32((r)[5] + F); \
		(r)[6] = SPH_T32((r)[6] + G); \
		(r)[7] = SPH_T32((r)[7] + H); \
	} while (0)

#else

#define SHA2_ROUND_BODY(in, r)   do { \
		sph_u32 A, B, C, D, E, F, G, H, T1, T2; \
		sph_u32 W00, W01, W02, W03, W04, W05, W06, W07; \
		sph_u32 W08, W09, W10, W11, W12, W13, W14, W15; \
 \
		A = (r)[0]; \
		B = (r)[1]; \
		C = (r)[2]; \
		D = (r)[3]; \
		E = (r)[4]; \
		F = (r)[5]; \
		G = (r)[6]; \
		H = (r)[7]; \
		W00 = in(0); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0x428A2F98) + W00); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W01 = in(1); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0x71374491) + W01); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W02 = in(2); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0xB5C0FBCF) + W02); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W03 = in(3); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0xE9B5DBA5) + W03); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W04 = in(4); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0x3956C25B) + W04); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W05 = in(5); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0x59F111F1) + W05); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W06 = in(6); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0x923F82A4) + W06); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W07 = in(7); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0xAB1C5ED5) + W07); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		W08 = in(8); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0xD807AA98) + W08); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W09 = in(9); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0x12835B01) + W09); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W10 = in(10); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0x243185BE) + W10); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W11 = in(11); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0x550C7DC3) + W11); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W12 = in(12); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0x72BE5D74) + W12); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W13 = in(13); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0x80DEB1FE) + W13); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W14 = in(14); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0x9BDC06A7) + W14); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W15 = in(15); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0xC19BF174) + W15); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		W00 = SPH_T32(SSG2_1(W14) + W09 + SSG2_0(W01) + W00); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0xE49B69C1) + W00); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W01 = SPH_T32(SSG2_1(W15) + W10 + SSG2_0(W02) + W01); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0xEFBE4786) + W01); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W02 = SPH_T32(SSG2_1(W00) + W11 + SSG2_0(W03) + W02); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0x0FC19DC6) + W02); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W03 = SPH_T32(SSG2_1(W01) + W12 + SSG2_0(W04) + W03); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0x240CA1CC) + W03); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W04 = SPH_T32(SSG2_1(W02) + W13 + SSG2_0(W05) + W04); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0x2DE92C6F) + W04); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W05 = SPH_T32(SSG2_1(W03) + W14 + SSG2_0(W06) + W05); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0x4A7484AA) + W05); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W06 = SPH_T32(SSG2_1(W04) + W15 + SSG2_0(W07) + W06); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0x5CB0A9DC) + W06); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W07 = SPH_T32(SSG2_1(W05) + W00 + SSG2_0(W08) + W07); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0x76F988DA) + W07); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		W08 = SPH_T32(SSG2_1(W06) + W01 + SSG2_0(W09) + W08); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0x983E5152) + W08); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W09 = SPH_T32(SSG2_1(W07) + W02 + SSG2_0(W10) + W09); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0xA831C66D) + W09); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W10 = SPH_T32(SSG2_1(W08) + W03 + SSG2_0(W11) + W10); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0xB00327C8) + W10); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W11 = SPH_T32(SSG2_1(W09) + W04 + SSG2_0(W12) + W11); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0xBF597FC7) + W11); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W12 = SPH_T32(SSG2_1(W10) + W05 + SSG2_0(W13) + W12); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0xC6E00BF3) + W12); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W13 = SPH_T32(SSG2_1(W11) + W06 + SSG2_0(W14) + W13); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0xD5A79147) + W13); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W14 = SPH_T32(SSG2_1(W12) + W07 + SSG2_0(W15) + W14); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0x06CA6351) + W14); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W15 = SPH_T32(SSG2_1(W13) + W08 + SSG2_0(W00) + W15); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0x14292967) + W15); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		W00 = SPH_T32(SSG2_1(W14) + W09 + SSG2_0(W01) + W00); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0x27B70A85) + W00); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W01 = SPH_T32(SSG2_1(W15) + W10 + SSG2_0(W02) + W01); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0x2E1B2138) + W01); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W02 = SPH_T32(SSG2_1(W00) + W11 + SSG2_0(W03) + W02); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0x4D2C6DFC) + W02); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W03 = SPH_T32(SSG2_1(W01) + W12 + SSG2_0(W04) + W03); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0x53380D13) + W03); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W04 = SPH_T32(SSG2_1(W02) + W13 + SSG2_0(W05) + W04); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0x650A7354) + W04); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W05 = SPH_T32(SSG2_1(W03) + W14 + SSG2_0(W06) + W05); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0x766A0ABB) + W05); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W06 = SPH_T32(SSG2_1(W04) + W15 + SSG2_0(W07) + W06); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0x81C2C92E) + W06); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W07 = SPH_T32(SSG2_1(W05) + W00 + SSG2_0(W08) + W07); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0x92722C85) + W07); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		W08 = SPH_T32(SSG2_1(W06) + W01 + SSG2_0(W09) + W08); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0xA2BFE8A1) + W08); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W09 = SPH_T32(SSG2_1(W07) + W02 + SSG2_0(W10) + W09); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0xA81A664B) + W09); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W10 = SPH_T32(SSG2_1(W08) + W03 + SSG2_0(W11) + W10); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0xC24B8B70) + W10); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W11 = SPH_T32(SSG2_1(W09) + W04 + SSG2_0(W12) + W11); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0xC76C51A3) + W11); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W12 = SPH_T32(SSG2_1(W10) + W05 + SSG2_0(W13) + W12); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0xD192E819) + W12); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W13 = SPH_T32(SSG2_1(W11) + W06 + SSG2_0(W14) + W13); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0xD6990624) + W13); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W14 = SPH_T32(SSG2_1(W12) + W07 + SSG2_0(W15) + W14); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0xF40E3585) + W14); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W15 = SPH_T32(SSG2_1(W13) + W08 + SSG2_0(W00) + W15); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0x106AA070) + W15); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		W00 = SPH_T32(SSG2_1(W14) + W09 + SSG2_0(W01) + W00); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0x19A4C116) + W00); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W01 = SPH_T32(SSG2_1(W15) + W10 + SSG2_0(W02) + W01); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0x1E376C08) + W01); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W02 = SPH_T32(SSG2_1(W00) + W11 + SSG2_0(W03) + W02); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0x2748774C) + W02); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W03 = SPH_T32(SSG2_1(W01) + W12 + SSG2_0(W04) + W03); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0x34B0BCB5) + W03); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W04 = SPH_T32(SSG2_1(W02) + W13 + SSG2_0(W05) + W04); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0x391C0CB3) + W04); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W05 = SPH_T32(SSG2_1(W03) + W14 + SSG2_0(W06) + W05); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0x4ED8AA4A) + W05); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W06 = SPH_T32(SSG2_1(W04) + W15 + SSG2_0(W07) + W06); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0x5B9CCA4F) + W06); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W07 = SPH_T32(SSG2_1(W05) + W00 + SSG2_0(W08) + W07); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0x682E6FF3) + W07); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		W08 = SPH_T32(SSG2_1(W06) + W01 + SSG2_0(W09) + W08); \
		T1 = SPH_T32(H + BSG2_1(E) + CH(E, F, G) \
			+ SPH_C32(0x748F82EE) + W08); \
		T2 = SPH_T32(BSG2_0(A) + MAJ(A, B, C)); \
		D = SPH_T32(D + T1); \
		H = SPH_T32(T1 + T2); \
		W09 = SPH_T32(SSG2_1(W07) + W02 + SSG2_0(W10) + W09); \
		T1 = SPH_T32(G + BSG2_1(D) + CH(D, E, F) \
			+ SPH_C32(0x78A5636F) + W09); \
		T2 = SPH_T32(BSG2_0(H) + MAJ(H, A, B)); \
		C = SPH_T32(C + T1); \
		G = SPH_T32(T1 + T2); \
		W10 = SPH_T32(SSG2_1(W08) + W03 + SSG2_0(W11) + W10); \
		T1 = SPH_T32(F + BSG2_1(C) + CH(C, D, E) \
			+ SPH_C32(0x84C87814) + W10); \
		T2 = SPH_T32(BSG2_0(G) + MAJ(G, H, A)); \
		B = SPH_T32(B + T1); \
		F = SPH_T32(T1 + T2); \
		W11 = SPH_T32(SSG2_1(W09) + W04 + SSG2_0(W12) + W11); \
		T1 = SPH_T32(E + BSG2_1(B) + CH(B, C, D) \
			+ SPH_C32(0x8CC70208) + W11); \
		T2 = SPH_T32(BSG2_0(F) + MAJ(F, G, H)); \
		A = SPH_T32(A + T1); \
		E = SPH_T32(T1 + T2); \
		W12 = SPH_T32(SSG2_1(W10) + W05 + SSG2_0(W13) + W12); \
		T1 = SPH_T32(D + BSG2_1(A) + CH(A, B, C) \
			+ SPH_C32(0x90BEFFFA) + W12); \
		T2 = SPH_T32(BSG2_0(E) + MAJ(E, F, G)); \
		H = SPH_T32(H + T1); \
		D = SPH_T32(T1 + T2); \
		W13 = SPH_T32(SSG2_1(W11) + W06 + SSG2_0(W14) + W13); \
		T1 = SPH_T32(C + BSG2_1(H) + CH(H, A, B) \
			+ SPH_C32(0xA4506CEB) + W13); \
		T2 = SPH_T32(BSG2_0(D) + MAJ(D, E, F)); \
		G = SPH_T32(G + T1); \
		C = SPH_T32(T1 + T2); \
		W14 = SPH_T32(SSG2_1(W12) + W07 + SSG2_0(W15) + W14); \
		T1 = SPH_T32(B + BSG2_1(G) + CH(G, H, A) \
			+ SPH_C32(0xBEF9A3F7) + W14); \
		T2 = SPH_T32(BSG2_0(C) + MAJ(C, D, E)); \
		F = SPH_T32(F + T1); \
		B = SPH_T32(T1 + T2); \
		W15 = SPH_T32(SSG2_1(W13) + W08 + SSG2_0(W00) + W15); \
		T1 = SPH_T32(A + BSG2_1(F) + CH(F, G, H) \
			+ SPH_C32(0xC67178F2) + W15); \
		T2 = SPH_T32(BSG2_0(B) + MAJ(B, C, D)); \
		E = SPH_T32(E + T1); \
		A = SPH_T32(T1 + T2); \
		(r)[0] = SPH_T32((r)[0] + A); \
		(r)[1] = SPH_T32((r)[1] + B); \
		(r)[2] = SPH_T32((r)[2] + C); \
		(r)[3] = SPH_T32((r)[3] + D); \
		(r)[4] = SPH_T32((r)[4] + E); \
		(r)[5] = SPH_T32((r)[5] + F); \
		(r)[6] = SPH_T32((r)[6] + G); \
		(r)[7] = SPH_T32((r)[7] + H); \
	} while (0)

#endif

/*
 * One round of SHA-224 / SHA-256. The data must be aligned for 32-bit access.
 */
static void
sha2_round(const unsigned char *data, sph_u32 r[8])
{
#define SHA2_IN(x)   sph_dec32be_aligned(data + (4 * (x)))
	SHA2_ROUND_BODY(SHA2_IN, r);
#undef SHA2_IN
}

/* see sph_sha2.h */
void
sph_sha224_init(void *cc)
{
	sph_sha224_context *sc;

	sc = cc;
	memcpy(sc->val, H224, sizeof H224);
#if SPH_64
	sc->count = 0;
#else
	sc->count_high = sc->count_low = 0;
#endif
}

/* see sph_sha2.h */
void
sph_sha256_init(void *cc)
{
	sph_sha256_context *sc;

	sc = cc;
	memcpy(sc->val, H256, sizeof H256);
#if SPH_64
	sc->count = 0;
#else
	sc->count_high = sc->count_low = 0;
#endif
}

#define RFUN   sha2_round
#define HASH   sha224
#define BE32   1
#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

#undef SPH_XCAT
#define SPH_XCAT(a, b)     SPH_XCAT_(a, b)
#undef SPH_XCAT_
#define SPH_XCAT_(a, b)    a ## b

#undef SPH_BLEN
#undef SPH_WLEN
#if defined BE64 || defined LE64
#define SPH_BLEN    128U
#define SPH_WLEN      8U
#else
#define SPH_BLEN     64U
#define SPH_WLEN      4U
#endif

#ifdef BLEN
#undef SPH_BLEN
#define SPH_BLEN    BLEN
#endif

#undef SPH_MAXPAD
#if defined PLW1
#define SPH_MAXPAD   (SPH_BLEN - SPH_WLEN)
#elif defined PLW4
#define SPH_MAXPAD   (SPH_BLEN - (SPH_WLEN << 2))
#else
#define SPH_MAXPAD   (SPH_BLEN - (SPH_WLEN << 1))
#endif

#undef SPH_VAL
#undef SPH_NO_OUTPUT
#ifdef SVAL
#define SPH_VAL         SVAL
#define SPH_NO_OUTPUT   1
#else
#define SPH_VAL   sc->val
#endif

#ifndef CLOSE_ONLY

#ifdef SPH_UPTR
void
SPH_XCAT(HASH, _short)(void *cc, const void *data, size_t len)
#else
void
SPH_XCAT(sph_, HASH)(void *cc, const void *data, size_t len)
#endif
{
	SPH_XCAT(sph_, SPH_XCAT(HASH, _context)) *sc;
	unsigned current;

	sc = (SPH_XCAT(sph_, SPH_XCAT(HASH, _context))*) cc;
#if SPH_64
	current = (unsigned)sc->count & (SPH_BLEN - 1U);
#else
	current = (unsigned)sc->count_low & (SPH_BLEN - 1U);
#endif
	while (len > 0) {
		unsigned clen;
#if !SPH_64
		sph_u32 clow, clow2;
#endif

		clen = SPH_BLEN - current;
		if (clen > len)
			clen = len;
		memcpy(sc->buf + current, data, clen);
		data = (const unsigned char *)data + clen;
		current += clen;
		len -= clen;
		if (current == SPH_BLEN) {
			RFUN(sc->buf, SPH_VAL);
			current = 0;
		}
#if SPH_64
		sc->count += clen;
#else
		clow = sc->count_low;
		clow2 = SPH_T32(clow + clen);
		sc->count_low = clow2;
		if (clow2 < clow)
			sc->count_high ++;
#endif
	}
}

#ifdef SPH_UPTR
void
SPH_XCAT(sph_, HASH)(void *cc, const void *data, size_t len)
{
	SPH_XCAT(sph_, SPH_XCAT(HASH, _context)) *sc;
	unsigned current;
	size_t orig_len;
#if !SPH_64
	sph_u32 clow, clow2;
#endif

	if (len < (2 * SPH_BLEN)) {
		SPH_XCAT(HASH, _short)(cc, data, len);
		return;
	}
	sc = (SPH_XCAT(sph_, SPH_XCAT(HASH, _context))*) cc;
#if SPH_64
	current = (unsigned)sc->count & (SPH_BLEN - 1U);
#else
	current = (unsigned)sc->count_low & (SPH_BLEN - 1U);
#endif
	if (current > 0) {
		unsigned t;

		t = SPH_BLEN - current;
		SPH_XCAT(HASH, _short)(cc, data, t);
		data = (const unsigned char *)data + t;
		len -= t;
	}
#if !SPH_UNALIGNED
	if (((SPH_UPTR)data & (SPH_WLEN - 1U)) != 0) {
		SPH_XCAT(HASH, _short)(cc, data, len);
		return;
	}
#endif
	orig_len = len;
	while (len >= SPH_BLEN) {
		RFUN((const unsigned char*)data, SPH_VAL);
		len -= SPH_BLEN;
		data = (const unsigned char *)data + SPH_BLEN;
	}
	if (len > 0)
		memcpy(sc->buf, data, len);
#if SPH_64
	sc->count += (sph_u64)orig_len;
#else
	clow = sc->count_low;
	clow2 = SPH_T32(clow + orig_len);
	sc->count_low = clow2;
	if (clow2 < clow)
		sc->count_high ++;
	/*
	 * This code handles the improbable situation where "size_t" is
	 * greater than 32 bits, and yet we do not have a 64-bit type.
	 */
	orig_len >>= 12;
	orig_len >>= 10;
	orig_len >>= 10;
	sc->count_high += orig_len;
#endif
}
#endif

#endif

/*
 * Perform padding and produce result. The context is NOT reinitialized
 * by this function.
 */
void
SPH_XCAT(HASH, _addbits_and_close)(void *cc,
	unsigned ub, unsigned n, void *dst, unsigned rnum)
{
	SPH_XCAT(sph_, SPH_XCAT(HASH, _context)) *sc;
	unsigned current, u;
#if !SPH_64
	sph_u32 low, high;
#endif

	sc = (SPH_XCAT(sph_, SPH_XCAT(HASH, _context))*) cc;

#if SPH_64
	current = (unsigned)sc->count & (SPH_BLEN - 1U);
#else
	current = (unsigned)sc->count_low & (SPH_BLEN - 1U);
#endif
#ifdef PW01
	sc->buf[current ++] = (0x100 | (ub & 0xFF)) >> (8 - n);
#else
	{
		unsigned z;

		z = 0x80 >> n;
		sc->buf[current ++] = ((ub & -z) | z) & 0xFF;
	}
#endif
	if (current > SPH_MAXPAD) {
		memset(sc->buf + current, 0, SPH_BLEN - current);
		RFUN(sc->buf, SPH_VAL);
		memset(sc->buf, 0, SPH_MAXPAD);
	} else {
		memset(sc->buf + current, 0, SPH_MAXPAD - current);
	}
#if defined BE64
#if defined PLW1
	sph_enc64be_aligned(sc->buf + SPH_MAXPAD,
		SPH_T64(sc->count << 3) + (sph_u64)n);
#elif defined PLW4
	memset(sc->buf + SPH_MAXPAD, 0, 2 * SPH_WLEN);
	sph_enc64be_aligned(sc->buf + SPH_MAXPAD + 2 * SPH_WLEN,
		sc->count >> 61);
	sph_enc64be_aligned(sc->buf + SPH_MAXPAD + 3 * SPH_WLEN,
		SPH_T64(sc->count << 3) + (sph_u64)n);
#else
	sph_enc64be_aligned(sc->buf + SPH_MAXPAD, sc->count >> 61);
	sph_enc64be_aligned(sc->buf + SPH_MAXPAD + SPH_WLEN,
		SPH_T64(sc->count << 3) + (sph_u64)n);
#endif
#elif defined LE64
#if defined PLW1
	sph_enc64le_aligned(sc->buf + SPH_MAXPAD,
		SPH_T64(sc->count << 3) + (sph_u64)n);
#elif defined PLW1
	sph_enc64le_aligned(sc->buf + SPH_MAXPAD,
		SPH_T64(sc->count << 3) + (sph_u64)n);
	sph_enc64le_aligned(sc->buf + SPH_MAXPAD + SPH_WLEN, sc->count >> 61);
	memset(sc->buf + SPH_MAXPAD + 2 * SPH_WLEN, 0, 2 * SPH_WLEN);
#else
	sph_enc64le_aligned(sc->buf + SPH_MAXPAD,
		SPH_T64(sc->count << 3) + (sph_u64)n);
	sph_enc64le_aligned(sc->buf + SPH_MAXPAD + SPH_WLEN, sc->count >> 61);
#endif
#else
#if SPH_64
#ifdef BE32
	sph_enc64be_aligned(sc->buf + SPH_MAXPAD,
		SPH_T64(sc->count << 3) + (sph_u64)n);
#else
	sph_enc64le_aligned(sc->buf + SPH_MAXPAD,
		SPH_T64(sc->count << 3) + (sph_u64)n);
#endif
#else
	low = sc->count_low;
	high = SPH_T32((sc->count_high << 3) | (low >> 29));
	low = SPH_T32(low << 3) + (sph_u32)n;
#ifdef BE32
	sph_enc32be(sc->buf + SPH_MAXPAD, high);
	sph_enc32be(sc->buf + SPH_MAXPAD + SPH_WLEN, low);
#else
	sph_enc32le(sc->buf + SPH_MAXPAD, low);
	sph_enc32le(sc->buf + SPH_MAXPAD + SPH_WLEN, high);
#endif
#endif
#endif
	RFUN(sc->buf, SPH_VAL);
#ifdef SPH_NO_OUTPUT
	(void)dst;
	(void)rnum;
	(void)u;
#else
	for (u = 0; u < rnum; u ++) {
#if defined BE64
		sph_enc64be((unsigned char *)dst + 8 * u, sc->val[u]);
#elif defined LE64
		sph_enc64le((unsigned char *)dst + 8 * u, sc->val[u]);
#elif defined BE32
		sph_enc32be((unsigned char *)dst + 4 * u, sc->val[u]);
#else
		sph_enc32le((unsigned char *)dst + 4 * u, sc->val[u]);
#endif
	}
#endif
}

void
SPH_XCAT(HASH, _close)(void *cc, void *dst, unsigned rnum)
{
	SPH_XCAT(HASH, _addbits_and_close)(cc, 0, 0, dst, rnum);
}

/* see sph_sha2.h */
void
sph_sha224_close(void *cc, void *dst)
{
	sha224_close(cc, dst, 7);
	sph_sha224_init(cc);
}

/* see sph_sha2.h */
void
sph_sha224_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	sha224_addbits_and_close(cc, ub, n, dst, 7);
	sph_sha224_init(cc);
}

/* see sph_sha2.h */
void
sph_sha256_close(void *cc, void *dst)
{
	sha224_close(cc, dst, 8);
	sph_sha256_init(cc);
}

/* see sph_sha2.h */
void
sph_sha256_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	sha224_addbits_and_close(cc, ub, n, dst, 8);
	sph_sha256_init(cc);
}

/* see sph_sha2.h */
void
sph_sha224_comp(const sph_u32 msg[16], sph_u32 val[8])
{
#define SHA2_IN(x)   msg[x]
	SHA2_ROUND_BODY(SHA2_IN, val);
#undef SHA2_IN
}

/* see sph_sha3.h */
void
sph_sha384_close(void *cc, void *dst)
{
	sha384_close(cc, dst, 6);
	sph_sha384_init(cc);
}

/* see sph_sha3.h */
void
sph_sha384_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	sha384_addbits_and_close(cc, ub, n, dst, 6);
	sph_sha384_init(cc);
}

/* see sph_sha3.h */
void
sph_sha512_close(void *cc, void *dst)
{
	sha384_close(cc, dst, 8);
	sph_sha512_init(cc);
}

/* see sph_sha3.h */
void
sph_sha512_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	sha384_addbits_and_close(cc, ub, n, dst, 8);
	sph_sha512_init(cc);
}

/* see sph_sha3.h */
void
sph_sha384_comp(const sph_u64 msg[16], sph_u64 val[8])
{
#define SHA3_IN(x)   msg[x]
	SHA3_ROUND_BODY(SHA3_IN, val);
#undef SHA3_IN
}

#ifdef __cplusplus
}
#endif

#endif
