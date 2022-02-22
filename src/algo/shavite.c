/* $Id: shavite.c 227 2010-06-16 17:28:38Z tp $ */
/*
 * SHAvite-3 implementation.
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

#include "sph_shavite.h"

#ifdef __cplusplus
extern "C"{
#endif

#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_SHAVITE
#define SPH_SMALL_FOOTPRINT_SHAVITE   1
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

#define C32   SPH_C32

/*
 * As of round 2 of the SHA-3 competition, the published reference
 * implementation and test vectors are wrong, because they use
 * big-endian AES tables while the internal decoding uses little-endian.
 * The code below follows the specification. To turn it into a code
 * which follows the reference implementation (the one called "BugFix"
 * on the SHAvite-3 web site, published on Nov 23rd, 2009), comment out
 * the code below (from the '#define AES_BIG_ENDIAN...' to the definition
 * of the AES_ROUND_NOKEY macro) and replace it with the version which
 * is commented out afterwards.
 */

#define AES_BIG_ENDIAN   0
#include "sph_types.h"
#ifdef __cplusplus
extern "C"{
#endif
#if AES_BIG_ENDIAN

#define AESx(x)   ( ((SPH_C32(x) >> 24) & SPH_C32(0x000000FF)) \
                  | ((SPH_C32(x) >>  8) & SPH_C32(0x0000FF00)) \
                  | ((SPH_C32(x) <<  8) & SPH_C32(0x00FF0000)) \
                  | ((SPH_C32(x) << 24) & SPH_C32(0xFF000000)))

#define AES0      AES0_BE
#define AES1      AES1_BE
#define AES2      AES2_BE
#define AES3      AES3_BE

#define AES_ROUND_BE(X0, X1, X2, X3, K0, K1, K2, K3, Y0, Y1, Y2, Y3)   do { \
		(Y0) = AES0[((X0) >> 24) & 0xFF] \
			^ AES1[((X1) >> 16) & 0xFF] \
			^ AES2[((X2) >> 8) & 0xFF] \
			^ AES3[(X3) & 0xFF] ^ (K0); \
		(Y1) = AES0[((X1) >> 24) & 0xFF] \
			^ AES1[((X2) >> 16) & 0xFF] \
			^ AES2[((X3) >> 8) & 0xFF] \
			^ AES3[(X0) & 0xFF] ^ (K1); \
		(Y2) = AES0[((X2) >> 24) & 0xFF] \
			^ AES1[((X3) >> 16) & 0xFF] \
			^ AES2[((X0) >> 8) & 0xFF] \
			^ AES3[(X1) & 0xFF] ^ (K2); \
		(Y3) = AES0[((X3) >> 24) & 0xFF] \
			^ AES1[((X0) >> 16) & 0xFF] \
			^ AES2[((X1) >> 8) & 0xFF] \
			^ AES3[(X2) & 0xFF] ^ (K3); \
	} while (0)

#define AES_ROUND_NOKEY_BE(X0, X1, X2, X3, Y0, Y1, Y2, Y3) \
	AES_ROUND_BE(X0, X1, X2, X3, 0, 0, 0, 0, Y0, Y1, Y2, Y3)

#else

#define AESx(x)   SPH_C32(x)
#define AES0      AES0_LE
#define AES1      AES1_LE
#define AES2      AES2_LE
#define AES3      AES3_LE

#define AES_ROUND_LE(X0, X1, X2, X3, K0, K1, K2, K3, Y0, Y1, Y2, Y3)   do { \
		(Y0) = AES0[(X0) & 0xFF] \
			^ AES1[((X1) >> 8) & 0xFF] \
			^ AES2[((X2) >> 16) & 0xFF] \
			^ AES3[((X3) >> 24) & 0xFF] ^ (K0); \
		(Y1) = AES0[(X1) & 0xFF] \
			^ AES1[((X2) >> 8) & 0xFF] \
			^ AES2[((X3) >> 16) & 0xFF] \
			^ AES3[((X0) >> 24) & 0xFF] ^ (K1); \
		(Y2) = AES0[(X2) & 0xFF] \
			^ AES1[((X3) >> 8) & 0xFF] \
			^ AES2[((X0) >> 16) & 0xFF] \
			^ AES3[((X1) >> 24) & 0xFF] ^ (K2); \
		(Y3) = AES0[(X3) & 0xFF] \
			^ AES1[((X0) >> 8) & 0xFF] \
			^ AES2[((X1) >> 16) & 0xFF] \
			^ AES3[((X2) >> 24) & 0xFF] ^ (K3); \
	} while (0)

#define AES_ROUND_NOKEY_LE(X0, X1, X2, X3, Y0, Y1, Y2, Y3) \
	AES_ROUND_LE(X0, X1, X2, X3, 0, 0, 0, 0, Y0, Y1, Y2, Y3)

#endif

/*
 * The AES*[] tables allow us to perform a fast evaluation of an AES
 * round; table AESi[] combines SubBytes for a byte at row i, and
 * MixColumns for the column where that byte goes after ShiftRows.
 */

static const sph_u32 AES0[256] = {
	AESx(0xA56363C6), AESx(0x847C7CF8), AESx(0x997777EE), AESx(0x8D7B7BF6),
	AESx(0x0DF2F2FF), AESx(0xBD6B6BD6), AESx(0xB16F6FDE), AESx(0x54C5C591),
	AESx(0x50303060), AESx(0x03010102), AESx(0xA96767CE), AESx(0x7D2B2B56),
	AESx(0x19FEFEE7), AESx(0x62D7D7B5), AESx(0xE6ABAB4D), AESx(0x9A7676EC),
	AESx(0x45CACA8F), AESx(0x9D82821F), AESx(0x40C9C989), AESx(0x877D7DFA),
	AESx(0x15FAFAEF), AESx(0xEB5959B2), AESx(0xC947478E), AESx(0x0BF0F0FB),
	AESx(0xECADAD41), AESx(0x67D4D4B3), AESx(0xFDA2A25F), AESx(0xEAAFAF45),
	AESx(0xBF9C9C23), AESx(0xF7A4A453), AESx(0x967272E4), AESx(0x5BC0C09B),
	AESx(0xC2B7B775), AESx(0x1CFDFDE1), AESx(0xAE93933D), AESx(0x6A26264C),
	AESx(0x5A36366C), AESx(0x413F3F7E), AESx(0x02F7F7F5), AESx(0x4FCCCC83),
	AESx(0x5C343468), AESx(0xF4A5A551), AESx(0x34E5E5D1), AESx(0x08F1F1F9),
	AESx(0x937171E2), AESx(0x73D8D8AB), AESx(0x53313162), AESx(0x3F15152A),
	AESx(0x0C040408), AESx(0x52C7C795), AESx(0x65232346), AESx(0x5EC3C39D),
	AESx(0x28181830), AESx(0xA1969637), AESx(0x0F05050A), AESx(0xB59A9A2F),
	AESx(0x0907070E), AESx(0x36121224), AESx(0x9B80801B), AESx(0x3DE2E2DF),
	AESx(0x26EBEBCD), AESx(0x6927274E), AESx(0xCDB2B27F), AESx(0x9F7575EA),
	AESx(0x1B090912), AESx(0x9E83831D), AESx(0x742C2C58), AESx(0x2E1A1A34),
	AESx(0x2D1B1B36), AESx(0xB26E6EDC), AESx(0xEE5A5AB4), AESx(0xFBA0A05B),
	AESx(0xF65252A4), AESx(0x4D3B3B76), AESx(0x61D6D6B7), AESx(0xCEB3B37D),
	AESx(0x7B292952), AESx(0x3EE3E3DD), AESx(0x712F2F5E), AESx(0x97848413),
	AESx(0xF55353A6), AESx(0x68D1D1B9), AESx(0x00000000), AESx(0x2CEDEDC1),
	AESx(0x60202040), AESx(0x1FFCFCE3), AESx(0xC8B1B179), AESx(0xED5B5BB6),
	AESx(0xBE6A6AD4), AESx(0x46CBCB8D), AESx(0xD9BEBE67), AESx(0x4B393972),
	AESx(0xDE4A4A94), AESx(0xD44C4C98), AESx(0xE85858B0), AESx(0x4ACFCF85),
	AESx(0x6BD0D0BB), AESx(0x2AEFEFC5), AESx(0xE5AAAA4F), AESx(0x16FBFBED),
	AESx(0xC5434386), AESx(0xD74D4D9A), AESx(0x55333366), AESx(0x94858511),
	AESx(0xCF45458A), AESx(0x10F9F9E9), AESx(0x06020204), AESx(0x817F7FFE),
	AESx(0xF05050A0), AESx(0x443C3C78), AESx(0xBA9F9F25), AESx(0xE3A8A84B),
	AESx(0xF35151A2), AESx(0xFEA3A35D), AESx(0xC0404080), AESx(0x8A8F8F05),
	AESx(0xAD92923F), AESx(0xBC9D9D21), AESx(0x48383870), AESx(0x04F5F5F1),
	AESx(0xDFBCBC63), AESx(0xC1B6B677), AESx(0x75DADAAF), AESx(0x63212142),
	AESx(0x30101020), AESx(0x1AFFFFE5), AESx(0x0EF3F3FD), AESx(0x6DD2D2BF),
	AESx(0x4CCDCD81), AESx(0x140C0C18), AESx(0x35131326), AESx(0x2FECECC3),
	AESx(0xE15F5FBE), AESx(0xA2979735), AESx(0xCC444488), AESx(0x3917172E),
	AESx(0x57C4C493), AESx(0xF2A7A755), AESx(0x827E7EFC), AESx(0x473D3D7A),
	AESx(0xAC6464C8), AESx(0xE75D5DBA), AESx(0x2B191932), AESx(0x957373E6),
	AESx(0xA06060C0), AESx(0x98818119), AESx(0xD14F4F9E), AESx(0x7FDCDCA3),
	AESx(0x66222244), AESx(0x7E2A2A54), AESx(0xAB90903B), AESx(0x8388880B),
	AESx(0xCA46468C), AESx(0x29EEEEC7), AESx(0xD3B8B86B), AESx(0x3C141428),
	AESx(0x79DEDEA7), AESx(0xE25E5EBC), AESx(0x1D0B0B16), AESx(0x76DBDBAD),
	AESx(0x3BE0E0DB), AESx(0x56323264), AESx(0x4E3A3A74), AESx(0x1E0A0A14),
	AESx(0xDB494992), AESx(0x0A06060C), AESx(0x6C242448), AESx(0xE45C5CB8),
	AESx(0x5DC2C29F), AESx(0x6ED3D3BD), AESx(0xEFACAC43), AESx(0xA66262C4),
	AESx(0xA8919139), AESx(0xA4959531), AESx(0x37E4E4D3), AESx(0x8B7979F2),
	AESx(0x32E7E7D5), AESx(0x43C8C88B), AESx(0x5937376E), AESx(0xB76D6DDA),
	AESx(0x8C8D8D01), AESx(0x64D5D5B1), AESx(0xD24E4E9C), AESx(0xE0A9A949),
	AESx(0xB46C6CD8), AESx(0xFA5656AC), AESx(0x07F4F4F3), AESx(0x25EAEACF),
	AESx(0xAF6565CA), AESx(0x8E7A7AF4), AESx(0xE9AEAE47), AESx(0x18080810),
	AESx(0xD5BABA6F), AESx(0x887878F0), AESx(0x6F25254A), AESx(0x722E2E5C),
	AESx(0x241C1C38), AESx(0xF1A6A657), AESx(0xC7B4B473), AESx(0x51C6C697),
	AESx(0x23E8E8CB), AESx(0x7CDDDDA1), AESx(0x9C7474E8), AESx(0x211F1F3E),
	AESx(0xDD4B4B96), AESx(0xDCBDBD61), AESx(0x868B8B0D), AESx(0x858A8A0F),
	AESx(0x907070E0), AESx(0x423E3E7C), AESx(0xC4B5B571), AESx(0xAA6666CC),
	AESx(0xD8484890), AESx(0x05030306), AESx(0x01F6F6F7), AESx(0x120E0E1C),
	AESx(0xA36161C2), AESx(0x5F35356A), AESx(0xF95757AE), AESx(0xD0B9B969),
	AESx(0x91868617), AESx(0x58C1C199), AESx(0x271D1D3A), AESx(0xB99E9E27),
	AESx(0x38E1E1D9), AESx(0x13F8F8EB), AESx(0xB398982B), AESx(0x33111122),
	AESx(0xBB6969D2), AESx(0x70D9D9A9), AESx(0x898E8E07), AESx(0xA7949433),
	AESx(0xB69B9B2D), AESx(0x221E1E3C), AESx(0x92878715), AESx(0x20E9E9C9),
	AESx(0x49CECE87), AESx(0xFF5555AA), AESx(0x78282850), AESx(0x7ADFDFA5),
	AESx(0x8F8C8C03), AESx(0xF8A1A159), AESx(0x80898909), AESx(0x170D0D1A),
	AESx(0xDABFBF65), AESx(0x31E6E6D7), AESx(0xC6424284), AESx(0xB86868D0),
	AESx(0xC3414182), AESx(0xB0999929), AESx(0x772D2D5A), AESx(0x110F0F1E),
	AESx(0xCBB0B07B), AESx(0xFC5454A8), AESx(0xD6BBBB6D), AESx(0x3A16162C)
};

static const sph_u32 AES1[256] = {
	AESx(0x6363C6A5), AESx(0x7C7CF884), AESx(0x7777EE99), AESx(0x7B7BF68D),
	AESx(0xF2F2FF0D), AESx(0x6B6BD6BD), AESx(0x6F6FDEB1), AESx(0xC5C59154),
	AESx(0x30306050), AESx(0x01010203), AESx(0x6767CEA9), AESx(0x2B2B567D),
	AESx(0xFEFEE719), AESx(0xD7D7B562), AESx(0xABAB4DE6), AESx(0x7676EC9A),
	AESx(0xCACA8F45), AESx(0x82821F9D), AESx(0xC9C98940), AESx(0x7D7DFA87),
	AESx(0xFAFAEF15), AESx(0x5959B2EB), AESx(0x47478EC9), AESx(0xF0F0FB0B),
	AESx(0xADAD41EC), AESx(0xD4D4B367), AESx(0xA2A25FFD), AESx(0xAFAF45EA),
	AESx(0x9C9C23BF), AESx(0xA4A453F7), AESx(0x7272E496), AESx(0xC0C09B5B),
	AESx(0xB7B775C2), AESx(0xFDFDE11C), AESx(0x93933DAE), AESx(0x26264C6A),
	AESx(0x36366C5A), AESx(0x3F3F7E41), AESx(0xF7F7F502), AESx(0xCCCC834F),
	AESx(0x3434685C), AESx(0xA5A551F4), AESx(0xE5E5D134), AESx(0xF1F1F908),
	AESx(0x7171E293), AESx(0xD8D8AB73), AESx(0x31316253), AESx(0x15152A3F),
	AESx(0x0404080C), AESx(0xC7C79552), AESx(0x23234665), AESx(0xC3C39D5E),
	AESx(0x18183028), AESx(0x969637A1), AESx(0x05050A0F), AESx(0x9A9A2FB5),
	AESx(0x07070E09), AESx(0x12122436), AESx(0x80801B9B), AESx(0xE2E2DF3D),
	AESx(0xEBEBCD26), AESx(0x27274E69), AESx(0xB2B27FCD), AESx(0x7575EA9F),
	AESx(0x0909121B), AESx(0x83831D9E), AESx(0x2C2C5874), AESx(0x1A1A342E),
	AESx(0x1B1B362D), AESx(0x6E6EDCB2), AESx(0x5A5AB4EE), AESx(0xA0A05BFB),
	AESx(0x5252A4F6), AESx(0x3B3B764D), AESx(0xD6D6B761), AESx(0xB3B37DCE),
	AESx(0x2929527B), AESx(0xE3E3DD3E), AESx(0x2F2F5E71), AESx(0x84841397),
	AESx(0x5353A6F5), AESx(0xD1D1B968), AESx(0x00000000), AESx(0xEDEDC12C),
	AESx(0x20204060), AESx(0xFCFCE31F), AESx(0xB1B179C8), AESx(0x5B5BB6ED),
	AESx(0x6A6AD4BE), AESx(0xCBCB8D46), AESx(0xBEBE67D9), AESx(0x3939724B),
	AESx(0x4A4A94DE), AESx(0x4C4C98D4), AESx(0x5858B0E8), AESx(0xCFCF854A),
	AESx(0xD0D0BB6B), AESx(0xEFEFC52A), AESx(0xAAAA4FE5), AESx(0xFBFBED16),
	AESx(0x434386C5), AESx(0x4D4D9AD7), AESx(0x33336655), AESx(0x85851194),
	AESx(0x45458ACF), AESx(0xF9F9E910), AESx(0x02020406), AESx(0x7F7FFE81),
	AESx(0x5050A0F0), AESx(0x3C3C7844), AESx(0x9F9F25BA), AESx(0xA8A84BE3),
	AESx(0x5151A2F3), AESx(0xA3A35DFE), AESx(0x404080C0), AESx(0x8F8F058A),
	AESx(0x92923FAD), AESx(0x9D9D21BC), AESx(0x38387048), AESx(0xF5F5F104),
	AESx(0xBCBC63DF), AESx(0xB6B677C1), AESx(0xDADAAF75), AESx(0x21214263),
	AESx(0x10102030), AESx(0xFFFFE51A), AESx(0xF3F3FD0E), AESx(0xD2D2BF6D),
	AESx(0xCDCD814C), AESx(0x0C0C1814), AESx(0x13132635), AESx(0xECECC32F),
	AESx(0x5F5FBEE1), AESx(0x979735A2), AESx(0x444488CC), AESx(0x17172E39),
	AESx(0xC4C49357), AESx(0xA7A755F2), AESx(0x7E7EFC82), AESx(0x3D3D7A47),
	AESx(0x6464C8AC), AESx(0x5D5DBAE7), AESx(0x1919322B), AESx(0x7373E695),
	AESx(0x6060C0A0), AESx(0x81811998), AESx(0x4F4F9ED1), AESx(0xDCDCA37F),
	AESx(0x22224466), AESx(0x2A2A547E), AESx(0x90903BAB), AESx(0x88880B83),
	AESx(0x46468CCA), AESx(0xEEEEC729), AESx(0xB8B86BD3), AESx(0x1414283C),
	AESx(0xDEDEA779), AESx(0x5E5EBCE2), AESx(0x0B0B161D), AESx(0xDBDBAD76),
	AESx(0xE0E0DB3B), AESx(0x32326456), AESx(0x3A3A744E), AESx(0x0A0A141E),
	AESx(0x494992DB), AESx(0x06060C0A), AESx(0x2424486C), AESx(0x5C5CB8E4),
	AESx(0xC2C29F5D), AESx(0xD3D3BD6E), AESx(0xACAC43EF), AESx(0x6262C4A6),
	AESx(0x919139A8), AESx(0x959531A4), AESx(0xE4E4D337), AESx(0x7979F28B),
	AESx(0xE7E7D532), AESx(0xC8C88B43), AESx(0x37376E59), AESx(0x6D6DDAB7),
	AESx(0x8D8D018C), AESx(0xD5D5B164), AESx(0x4E4E9CD2), AESx(0xA9A949E0),
	AESx(0x6C6CD8B4), AESx(0x5656ACFA), AESx(0xF4F4F307), AESx(0xEAEACF25),
	AESx(0x6565CAAF), AESx(0x7A7AF48E), AESx(0xAEAE47E9), AESx(0x08081018),
	AESx(0xBABA6FD5), AESx(0x7878F088), AESx(0x25254A6F), AESx(0x2E2E5C72),
	AESx(0x1C1C3824), AESx(0xA6A657F1), AESx(0xB4B473C7), AESx(0xC6C69751),
	AESx(0xE8E8CB23), AESx(0xDDDDA17C), AESx(0x7474E89C), AESx(0x1F1F3E21),
	AESx(0x4B4B96DD), AESx(0xBDBD61DC), AESx(0x8B8B0D86), AESx(0x8A8A0F85),
	AESx(0x7070E090), AESx(0x3E3E7C42), AESx(0xB5B571C4), AESx(0x6666CCAA),
	AESx(0x484890D8), AESx(0x03030605), AESx(0xF6F6F701), AESx(0x0E0E1C12),
	AESx(0x6161C2A3), AESx(0x35356A5F), AESx(0x5757AEF9), AESx(0xB9B969D0),
	AESx(0x86861791), AESx(0xC1C19958), AESx(0x1D1D3A27), AESx(0x9E9E27B9),
	AESx(0xE1E1D938), AESx(0xF8F8EB13), AESx(0x98982BB3), AESx(0x11112233),
	AESx(0x6969D2BB), AESx(0xD9D9A970), AESx(0x8E8E0789), AESx(0x949433A7),
	AESx(0x9B9B2DB6), AESx(0x1E1E3C22), AESx(0x87871592), AESx(0xE9E9C920),
	AESx(0xCECE8749), AESx(0x5555AAFF), AESx(0x28285078), AESx(0xDFDFA57A),
	AESx(0x8C8C038F), AESx(0xA1A159F8), AESx(0x89890980), AESx(0x0D0D1A17),
	AESx(0xBFBF65DA), AESx(0xE6E6D731), AESx(0x424284C6), AESx(0x6868D0B8),
	AESx(0x414182C3), AESx(0x999929B0), AESx(0x2D2D5A77), AESx(0x0F0F1E11),
	AESx(0xB0B07BCB), AESx(0x5454A8FC), AESx(0xBBBB6DD6), AESx(0x16162C3A)
};

static const sph_u32 AES2[256] = {
	AESx(0x63C6A563), AESx(0x7CF8847C), AESx(0x77EE9977), AESx(0x7BF68D7B),
	AESx(0xF2FF0DF2), AESx(0x6BD6BD6B), AESx(0x6FDEB16F), AESx(0xC59154C5),
	AESx(0x30605030), AESx(0x01020301), AESx(0x67CEA967), AESx(0x2B567D2B),
	AESx(0xFEE719FE), AESx(0xD7B562D7), AESx(0xAB4DE6AB), AESx(0x76EC9A76),
	AESx(0xCA8F45CA), AESx(0x821F9D82), AESx(0xC98940C9), AESx(0x7DFA877D),
	AESx(0xFAEF15FA), AESx(0x59B2EB59), AESx(0x478EC947), AESx(0xF0FB0BF0),
	AESx(0xAD41ECAD), AESx(0xD4B367D4), AESx(0xA25FFDA2), AESx(0xAF45EAAF),
	AESx(0x9C23BF9C), AESx(0xA453F7A4), AESx(0x72E49672), AESx(0xC09B5BC0),
	AESx(0xB775C2B7), AESx(0xFDE11CFD), AESx(0x933DAE93), AESx(0x264C6A26),
	AESx(0x366C5A36), AESx(0x3F7E413F), AESx(0xF7F502F7), AESx(0xCC834FCC),
	AESx(0x34685C34), AESx(0xA551F4A5), AESx(0xE5D134E5), AESx(0xF1F908F1),
	AESx(0x71E29371), AESx(0xD8AB73D8), AESx(0x31625331), AESx(0x152A3F15),
	AESx(0x04080C04), AESx(0xC79552C7), AESx(0x23466523), AESx(0xC39D5EC3),
	AESx(0x18302818), AESx(0x9637A196), AESx(0x050A0F05), AESx(0x9A2FB59A),
	AESx(0x070E0907), AESx(0x12243612), AESx(0x801B9B80), AESx(0xE2DF3DE2),
	AESx(0xEBCD26EB), AESx(0x274E6927), AESx(0xB27FCDB2), AESx(0x75EA9F75),
	AESx(0x09121B09), AESx(0x831D9E83), AESx(0x2C58742C), AESx(0x1A342E1A),
	AESx(0x1B362D1B), AESx(0x6EDCB26E), AESx(0x5AB4EE5A), AESx(0xA05BFBA0),
	AESx(0x52A4F652), AESx(0x3B764D3B), AESx(0xD6B761D6), AESx(0xB37DCEB3),
	AESx(0x29527B29), AESx(0xE3DD3EE3), AESx(0x2F5E712F), AESx(0x84139784),
	AESx(0x53A6F553), AESx(0xD1B968D1), AESx(0x00000000), AESx(0xEDC12CED),
	AESx(0x20406020), AESx(0xFCE31FFC), AESx(0xB179C8B1), AESx(0x5BB6ED5B),
	AESx(0x6AD4BE6A), AESx(0xCB8D46CB), AESx(0xBE67D9BE), AESx(0x39724B39),
	AESx(0x4A94DE4A), AESx(0x4C98D44C), AESx(0x58B0E858), AESx(0xCF854ACF),
	AESx(0xD0BB6BD0), AESx(0xEFC52AEF), AESx(0xAA4FE5AA), AESx(0xFBED16FB),
	AESx(0x4386C543), AESx(0x4D9AD74D), AESx(0x33665533), AESx(0x85119485),
	AESx(0x458ACF45), AESx(0xF9E910F9), AESx(0x02040602), AESx(0x7FFE817F),
	AESx(0x50A0F050), AESx(0x3C78443C), AESx(0x9F25BA9F), AESx(0xA84BE3A8),
	AESx(0x51A2F351), AESx(0xA35DFEA3), AESx(0x4080C040), AESx(0x8F058A8F),
	AESx(0x923FAD92), AESx(0x9D21BC9D), AESx(0x38704838), AESx(0xF5F104F5),
	AESx(0xBC63DFBC), AESx(0xB677C1B6), AESx(0xDAAF75DA), AESx(0x21426321),
	AESx(0x10203010), AESx(0xFFE51AFF), AESx(0xF3FD0EF3), AESx(0xD2BF6DD2),
	AESx(0xCD814CCD), AESx(0x0C18140C), AESx(0x13263513), AESx(0xECC32FEC),
	AESx(0x5FBEE15F), AESx(0x9735A297), AESx(0x4488CC44), AESx(0x172E3917),
	AESx(0xC49357C4), AESx(0xA755F2A7), AESx(0x7EFC827E), AESx(0x3D7A473D),
	AESx(0x64C8AC64), AESx(0x5DBAE75D), AESx(0x19322B19), AESx(0x73E69573),
	AESx(0x60C0A060), AESx(0x81199881), AESx(0x4F9ED14F), AESx(0xDCA37FDC),
	AESx(0x22446622), AESx(0x2A547E2A), AESx(0x903BAB90), AESx(0x880B8388),
	AESx(0x468CCA46), AESx(0xEEC729EE), AESx(0xB86BD3B8), AESx(0x14283C14),
	AESx(0xDEA779DE), AESx(0x5EBCE25E), AESx(0x0B161D0B), AESx(0xDBAD76DB),
	AESx(0xE0DB3BE0), AESx(0x32645632), AESx(0x3A744E3A), AESx(0x0A141E0A),
	AESx(0x4992DB49), AESx(0x060C0A06), AESx(0x24486C24), AESx(0x5CB8E45C),
	AESx(0xC29F5DC2), AESx(0xD3BD6ED3), AESx(0xAC43EFAC), AESx(0x62C4A662),
	AESx(0x9139A891), AESx(0x9531A495), AESx(0xE4D337E4), AESx(0x79F28B79),
	AESx(0xE7D532E7), AESx(0xC88B43C8), AESx(0x376E5937), AESx(0x6DDAB76D),
	AESx(0x8D018C8D), AESx(0xD5B164D5), AESx(0x4E9CD24E), AESx(0xA949E0A9),
	AESx(0x6CD8B46C), AESx(0x56ACFA56), AESx(0xF4F307F4), AESx(0xEACF25EA),
	AESx(0x65CAAF65), AESx(0x7AF48E7A), AESx(0xAE47E9AE), AESx(0x08101808),
	AESx(0xBA6FD5BA), AESx(0x78F08878), AESx(0x254A6F25), AESx(0x2E5C722E),
	AESx(0x1C38241C), AESx(0xA657F1A6), AESx(0xB473C7B4), AESx(0xC69751C6),
	AESx(0xE8CB23E8), AESx(0xDDA17CDD), AESx(0x74E89C74), AESx(0x1F3E211F),
	AESx(0x4B96DD4B), AESx(0xBD61DCBD), AESx(0x8B0D868B), AESx(0x8A0F858A),
	AESx(0x70E09070), AESx(0x3E7C423E), AESx(0xB571C4B5), AESx(0x66CCAA66),
	AESx(0x4890D848), AESx(0x03060503), AESx(0xF6F701F6), AESx(0x0E1C120E),
	AESx(0x61C2A361), AESx(0x356A5F35), AESx(0x57AEF957), AESx(0xB969D0B9),
	AESx(0x86179186), AESx(0xC19958C1), AESx(0x1D3A271D), AESx(0x9E27B99E),
	AESx(0xE1D938E1), AESx(0xF8EB13F8), AESx(0x982BB398), AESx(0x11223311),
	AESx(0x69D2BB69), AESx(0xD9A970D9), AESx(0x8E07898E), AESx(0x9433A794),
	AESx(0x9B2DB69B), AESx(0x1E3C221E), AESx(0x87159287), AESx(0xE9C920E9),
	AESx(0xCE8749CE), AESx(0x55AAFF55), AESx(0x28507828), AESx(0xDFA57ADF),
	AESx(0x8C038F8C), AESx(0xA159F8A1), AESx(0x89098089), AESx(0x0D1A170D),
	AESx(0xBF65DABF), AESx(0xE6D731E6), AESx(0x4284C642), AESx(0x68D0B868),
	AESx(0x4182C341), AESx(0x9929B099), AESx(0x2D5A772D), AESx(0x0F1E110F),
	AESx(0xB07BCBB0), AESx(0x54A8FC54), AESx(0xBB6DD6BB), AESx(0x162C3A16)
};

static const sph_u32 AES3[256] = {
	AESx(0xC6A56363), AESx(0xF8847C7C), AESx(0xEE997777), AESx(0xF68D7B7B),
	AESx(0xFF0DF2F2), AESx(0xD6BD6B6B), AESx(0xDEB16F6F), AESx(0x9154C5C5),
	AESx(0x60503030), AESx(0x02030101), AESx(0xCEA96767), AESx(0x567D2B2B),
	AESx(0xE719FEFE), AESx(0xB562D7D7), AESx(0x4DE6ABAB), AESx(0xEC9A7676),
	AESx(0x8F45CACA), AESx(0x1F9D8282), AESx(0x8940C9C9), AESx(0xFA877D7D),
	AESx(0xEF15FAFA), AESx(0xB2EB5959), AESx(0x8EC94747), AESx(0xFB0BF0F0),
	AESx(0x41ECADAD), AESx(0xB367D4D4), AESx(0x5FFDA2A2), AESx(0x45EAAFAF),
	AESx(0x23BF9C9C), AESx(0x53F7A4A4), AESx(0xE4967272), AESx(0x9B5BC0C0),
	AESx(0x75C2B7B7), AESx(0xE11CFDFD), AESx(0x3DAE9393), AESx(0x4C6A2626),
	AESx(0x6C5A3636), AESx(0x7E413F3F), AESx(0xF502F7F7), AESx(0x834FCCCC),
	AESx(0x685C3434), AESx(0x51F4A5A5), AESx(0xD134E5E5), AESx(0xF908F1F1),
	AESx(0xE2937171), AESx(0xAB73D8D8), AESx(0x62533131), AESx(0x2A3F1515),
	AESx(0x080C0404), AESx(0x9552C7C7), AESx(0x46652323), AESx(0x9D5EC3C3),
	AESx(0x30281818), AESx(0x37A19696), AESx(0x0A0F0505), AESx(0x2FB59A9A),
	AESx(0x0E090707), AESx(0x24361212), AESx(0x1B9B8080), AESx(0xDF3DE2E2),
	AESx(0xCD26EBEB), AESx(0x4E692727), AESx(0x7FCDB2B2), AESx(0xEA9F7575),
	AESx(0x121B0909), AESx(0x1D9E8383), AESx(0x58742C2C), AESx(0x342E1A1A),
	AESx(0x362D1B1B), AESx(0xDCB26E6E), AESx(0xB4EE5A5A), AESx(0x5BFBA0A0),
	AESx(0xA4F65252), AESx(0x764D3B3B), AESx(0xB761D6D6), AESx(0x7DCEB3B3),
	AESx(0x527B2929), AESx(0xDD3EE3E3), AESx(0x5E712F2F), AESx(0x13978484),
	AESx(0xA6F55353), AESx(0xB968D1D1), AESx(0x00000000), AESx(0xC12CEDED),
	AESx(0x40602020), AESx(0xE31FFCFC), AESx(0x79C8B1B1), AESx(0xB6ED5B5B),
	AESx(0xD4BE6A6A), AESx(0x8D46CBCB), AESx(0x67D9BEBE), AESx(0x724B3939),
	AESx(0x94DE4A4A), AESx(0x98D44C4C), AESx(0xB0E85858), AESx(0x854ACFCF),
	AESx(0xBB6BD0D0), AESx(0xC52AEFEF), AESx(0x4FE5AAAA), AESx(0xED16FBFB),
	AESx(0x86C54343), AESx(0x9AD74D4D), AESx(0x66553333), AESx(0x11948585),
	AESx(0x8ACF4545), AESx(0xE910F9F9), AESx(0x04060202), AESx(0xFE817F7F),
	AESx(0xA0F05050), AESx(0x78443C3C), AESx(0x25BA9F9F), AESx(0x4BE3A8A8),
	AESx(0xA2F35151), AESx(0x5DFEA3A3), AESx(0x80C04040), AESx(0x058A8F8F),
	AESx(0x3FAD9292), AESx(0x21BC9D9D), AESx(0x70483838), AESx(0xF104F5F5),
	AESx(0x63DFBCBC), AESx(0x77C1B6B6), AESx(0xAF75DADA), AESx(0x42632121),
	AESx(0x20301010), AESx(0xE51AFFFF), AESx(0xFD0EF3F3), AESx(0xBF6DD2D2),
	AESx(0x814CCDCD), AESx(0x18140C0C), AESx(0x26351313), AESx(0xC32FECEC),
	AESx(0xBEE15F5F), AESx(0x35A29797), AESx(0x88CC4444), AESx(0x2E391717),
	AESx(0x9357C4C4), AESx(0x55F2A7A7), AESx(0xFC827E7E), AESx(0x7A473D3D),
	AESx(0xC8AC6464), AESx(0xBAE75D5D), AESx(0x322B1919), AESx(0xE6957373),
	AESx(0xC0A06060), AESx(0x19988181), AESx(0x9ED14F4F), AESx(0xA37FDCDC),
	AESx(0x44662222), AESx(0x547E2A2A), AESx(0x3BAB9090), AESx(0x0B838888),
	AESx(0x8CCA4646), AESx(0xC729EEEE), AESx(0x6BD3B8B8), AESx(0x283C1414),
	AESx(0xA779DEDE), AESx(0xBCE25E5E), AESx(0x161D0B0B), AESx(0xAD76DBDB),
	AESx(0xDB3BE0E0), AESx(0x64563232), AESx(0x744E3A3A), AESx(0x141E0A0A),
	AESx(0x92DB4949), AESx(0x0C0A0606), AESx(0x486C2424), AESx(0xB8E45C5C),
	AESx(0x9F5DC2C2), AESx(0xBD6ED3D3), AESx(0x43EFACAC), AESx(0xC4A66262),
	AESx(0x39A89191), AESx(0x31A49595), AESx(0xD337E4E4), AESx(0xF28B7979),
	AESx(0xD532E7E7), AESx(0x8B43C8C8), AESx(0x6E593737), AESx(0xDAB76D6D),
	AESx(0x018C8D8D), AESx(0xB164D5D5), AESx(0x9CD24E4E), AESx(0x49E0A9A9),
	AESx(0xD8B46C6C), AESx(0xACFA5656), AESx(0xF307F4F4), AESx(0xCF25EAEA),
	AESx(0xCAAF6565), AESx(0xF48E7A7A), AESx(0x47E9AEAE), AESx(0x10180808),
	AESx(0x6FD5BABA), AESx(0xF0887878), AESx(0x4A6F2525), AESx(0x5C722E2E),
	AESx(0x38241C1C), AESx(0x57F1A6A6), AESx(0x73C7B4B4), AESx(0x9751C6C6),
	AESx(0xCB23E8E8), AESx(0xA17CDDDD), AESx(0xE89C7474), AESx(0x3E211F1F),
	AESx(0x96DD4B4B), AESx(0x61DCBDBD), AESx(0x0D868B8B), AESx(0x0F858A8A),
	AESx(0xE0907070), AESx(0x7C423E3E), AESx(0x71C4B5B5), AESx(0xCCAA6666),
	AESx(0x90D84848), AESx(0x06050303), AESx(0xF701F6F6), AESx(0x1C120E0E),
	AESx(0xC2A36161), AESx(0x6A5F3535), AESx(0xAEF95757), AESx(0x69D0B9B9),
	AESx(0x17918686), AESx(0x9958C1C1), AESx(0x3A271D1D), AESx(0x27B99E9E),
	AESx(0xD938E1E1), AESx(0xEB13F8F8), AESx(0x2BB39898), AESx(0x22331111),
	AESx(0xD2BB6969), AESx(0xA970D9D9), AESx(0x07898E8E), AESx(0x33A79494),
	AESx(0x2DB69B9B), AESx(0x3C221E1E), AESx(0x15928787), AESx(0xC920E9E9),
	AESx(0x8749CECE), AESx(0xAAFF5555), AESx(0x50782828), AESx(0xA57ADFDF),
	AESx(0x038F8C8C), AESx(0x59F8A1A1), AESx(0x09808989), AESx(0x1A170D0D),
	AESx(0x65DABFBF), AESx(0xD731E6E6), AESx(0x84C64242), AESx(0xD0B86868),
	AESx(0x82C34141), AESx(0x29B09999), AESx(0x5A772D2D), AESx(0x1E110F0F),
	AESx(0x7BCBB0B0), AESx(0xA8FC5454), AESx(0x6DD6BBBB), AESx(0x2C3A1616)
};

#ifdef __cplusplus
}
#endif

static const sph_u32 IV224[] = {
	C32(0x6774F31C), C32(0x990AE210), C32(0xC87D4274), C32(0xC9546371),
	C32(0x62B2AEA8), C32(0x4B5801D8), C32(0x1B702860), C32(0x842F3017)
};

static const sph_u32 IV256[] = {
	C32(0x49BB3E47), C32(0x2674860D), C32(0xA8B392AC), C32(0x021AC4E6),
	C32(0x409283CF), C32(0x620E5D86), C32(0x6D929DCB), C32(0x96CC2A8B)
};

static const sph_u32 IV384[] = {
	C32(0x83DF1545), C32(0xF9AAEC13), C32(0xF4803CB0), C32(0x11FE1F47),
	C32(0xDA6CD269), C32(0x4F53FCD7), C32(0x950529A2), C32(0x97908147),
	C32(0xB0A4D7AF), C32(0x2B9132BF), C32(0x226E607D), C32(0x3C0F8D7C),
	C32(0x487B3F0F), C32(0x04363E22), C32(0x0155C99C), C32(0xEC2E20D3)
};

static const sph_u32 IV512[] = {
	C32(0x72FCCDD8), C32(0x79CA4727), C32(0x128A077B), C32(0x40D55AEC),
	C32(0xD1901A06), C32(0x430AE307), C32(0xB29F5CD1), C32(0xDF07FBFC),
	C32(0x8E45D73D), C32(0x681AB538), C32(0xBDE86578), C32(0xDD577E47),
	C32(0xE275EADE), C32(0x502D9FCD), C32(0xB9357178), C32(0x022A4B9A)
};

#define AES_ROUND_NOKEY(x0, x1, x2, x3)   do { \
		sph_u32 t0 = (x0); \
		sph_u32 t1 = (x1); \
		sph_u32 t2 = (x2); \
		sph_u32 t3 = (x3); \
		AES_ROUND_NOKEY_LE(t0, t1, t2, t3, x0, x1, x2, x3); \
	} while (0)

/*
 * This is the code needed to match the "reference implementation" as
 * published on Nov 23rd, 2009, instead of the published specification.
 * 

#define AES_BIG_ENDIAN   1
#include "aes_helper.c"

static const sph_u32 IV224[] = {
	C32(0xC4C67795), C32(0xC0B1817F), C32(0xEAD88924), C32(0x1ABB1BB0),
	C32(0xE0C29152), C32(0xBDE046BA), C32(0xAEEECF99), C32(0x58D509D8)
};

static const sph_u32 IV256[] = {
	C32(0x3EECF551), C32(0xBF10819B), C32(0xE6DC8559), C32(0xF3E23FD5),
	C32(0x431AEC73), C32(0x79E3F731), C32(0x98325F05), C32(0xA92A31F1)
};

static const sph_u32 IV384[] = {
	C32(0x71F48510), C32(0xA903A8AC), C32(0xFE3216DD), C32(0x0B2D2AD4),
	C32(0x6672900A), C32(0x41032819), C32(0x15A7D780), C32(0xB3CAB8D9),
	C32(0x34EF4711), C32(0xDE019FE8), C32(0x4D674DC4), C32(0xE056D96B),
	C32(0xA35C016B), C32(0xDD903BA7), C32(0x8C1B09B4), C32(0x2C3E9F25)
};

static const sph_u32 IV512[] = {
	C32(0xD5652B63), C32(0x25F1E6EA), C32(0xB18F48FA), C32(0xA1EE3A47),
	C32(0xC8B67B07), C32(0xBDCE48D3), C32(0xE3937B78), C32(0x05DB5186),
	C32(0x613BE326), C32(0xA11FA303), C32(0x90C833D4), C32(0x79CEE316),
	C32(0x1E1AF00F), C32(0x2829B165), C32(0x23B25F80), C32(0x21E11499)
};

#define AES_ROUND_NOKEY(x0, x1, x2, x3)   do { \
		sph_u32 t0 = (x0); \
		sph_u32 t1 = (x1); \
		sph_u32 t2 = (x2); \
		sph_u32 t3 = (x3); \
		AES_ROUND_NOKEY_BE(t0, t1, t2, t3, x0, x1, x2, x3); \
	} while (0)

 */

#define KEY_EXPAND_ELT(k0, k1, k2, k3)   do { \
		sph_u32 kt; \
		AES_ROUND_NOKEY(k1, k2, k3, k0); \
		kt = (k0); \
		(k0) = (k1); \
		(k1) = (k2); \
		(k2) = (k3); \
		(k3) = kt; \
	} while (0)

#if SPH_SMALL_FOOTPRINT_SHAVITE

/*
 * This function assumes that "msg" is aligned for 32-bit access.
 */
static void
c256(sph_shavite_small_context *sc, const void *msg)
{
	sph_u32 p0, p1, p2, p3, p4, p5, p6, p7;
	sph_u32 rk[144];
	size_t u;
	int r, s;

#if SPH_LITTLE_ENDIAN
	memcpy(rk, msg, 64);
#else
	for (u = 0; u < 16; u += 4) {
		rk[u + 0] = sph_dec32le_aligned(
			(const unsigned char *)msg + (u << 2) +  0);
		rk[u + 1] = sph_dec32le_aligned(
			(const unsigned char *)msg + (u << 2) +  4);
		rk[u + 2] = sph_dec32le_aligned(
			(const unsigned char *)msg + (u << 2) +  8);
		rk[u + 3] = sph_dec32le_aligned(
			(const unsigned char *)msg + (u << 2) + 12);
	}
#endif
	u = 16;
	for (r = 0; r < 4; r ++) {
		for (s = 0; s < 2; s ++) {
			sph_u32 x0, x1, x2, x3;

			x0 = rk[u - 15];
			x1 = rk[u - 14];
			x2 = rk[u - 13];
			x3 = rk[u - 16];
			AES_ROUND_NOKEY(x0, x1, x2, x3);
			rk[u + 0] = x0 ^ rk[u - 4];
			rk[u + 1] = x1 ^ rk[u - 3];
			rk[u + 2] = x2 ^ rk[u - 2];
			rk[u + 3] = x3 ^ rk[u - 1];
			if (u == 16) {
				rk[ 16] ^= sc->count0;
				rk[ 17] ^= SPH_T32(~sc->count1);
			} else if (u == 56) {
				rk[ 57] ^= sc->count1;
				rk[ 58] ^= SPH_T32(~sc->count0);
			}
			u += 4;

			x0 = rk[u - 15];
			x1 = rk[u - 14];
			x2 = rk[u - 13];
			x3 = rk[u - 16];
			AES_ROUND_NOKEY(x0, x1, x2, x3);
			rk[u + 0] = x0 ^ rk[u - 4];
			rk[u + 1] = x1 ^ rk[u - 3];
			rk[u + 2] = x2 ^ rk[u - 2];
			rk[u + 3] = x3 ^ rk[u - 1];
			if (u == 84) {
				rk[ 86] ^= sc->count1;
				rk[ 87] ^= SPH_T32(~sc->count0);
			} else if (u == 124) {
				rk[124] ^= sc->count0;
				rk[127] ^= SPH_T32(~sc->count1);
			}
			u += 4;
		}
		for (s = 0; s < 4; s ++) {
			rk[u + 0] = rk[u - 16] ^ rk[u - 3];
			rk[u + 1] = rk[u - 15] ^ rk[u - 2];
			rk[u + 2] = rk[u - 14] ^ rk[u - 1];
			rk[u + 3] = rk[u - 13] ^ rk[u - 0];
			u += 4;
		}
	}

	p0 = sc->h[0x0];
	p1 = sc->h[0x1];
	p2 = sc->h[0x2];
	p3 = sc->h[0x3];
	p4 = sc->h[0x4];
	p5 = sc->h[0x5];
	p6 = sc->h[0x6];
	p7 = sc->h[0x7];
	u = 0;
	for (r = 0; r < 6; r ++) {
		sph_u32 x0, x1, x2, x3;

		x0 = p4 ^ rk[u ++];
		x1 = p5 ^ rk[u ++];
		x2 = p6 ^ rk[u ++];
		x3 = p7 ^ rk[u ++];
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		x0 ^= rk[u ++];
		x1 ^= rk[u ++];
		x2 ^= rk[u ++];
		x3 ^= rk[u ++];
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		x0 ^= rk[u ++];
		x1 ^= rk[u ++];
		x2 ^= rk[u ++];
		x3 ^= rk[u ++];
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		p0 ^= x0;
		p1 ^= x1;
		p2 ^= x2;
		p3 ^= x3;

		x0 = p0 ^ rk[u ++];
		x1 = p1 ^ rk[u ++];
		x2 = p2 ^ rk[u ++];
		x3 = p3 ^ rk[u ++];
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		x0 ^= rk[u ++];
		x1 ^= rk[u ++];
		x2 ^= rk[u ++];
		x3 ^= rk[u ++];
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		x0 ^= rk[u ++];
		x1 ^= rk[u ++];
		x2 ^= rk[u ++];
		x3 ^= rk[u ++];
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		p4 ^= x0;
		p5 ^= x1;
		p6 ^= x2;
		p7 ^= x3;
	}
	sc->h[0x0] ^= p0;
	sc->h[0x1] ^= p1;
	sc->h[0x2] ^= p2;
	sc->h[0x3] ^= p3;
	sc->h[0x4] ^= p4;
	sc->h[0x5] ^= p5;
	sc->h[0x6] ^= p6;
	sc->h[0x7] ^= p7;
}

#else

/*
 * This function assumes that "msg" is aligned for 32-bit access.
 */
static void
c256(sph_shavite_small_context *sc, const void *msg)
{
	sph_u32 p0, p1, p2, p3, p4, p5, p6, p7;
	sph_u32 x0, x1, x2, x3;
	sph_u32 rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7;
	sph_u32 rk8, rk9, rkA, rkB, rkC, rkD, rkE, rkF;

	p0 = sc->h[0x0];
	p1 = sc->h[0x1];
	p2 = sc->h[0x2];
	p3 = sc->h[0x3];
	p4 = sc->h[0x4];
	p5 = sc->h[0x5];
	p6 = sc->h[0x6];
	p7 = sc->h[0x7];
	/* round 0 */
	rk0 = sph_dec32le_aligned((const unsigned char *)msg +  0);
	x0 = p4 ^ rk0;
	rk1 = sph_dec32le_aligned((const unsigned char *)msg +  4);
	x1 = p5 ^ rk1;
	rk2 = sph_dec32le_aligned((const unsigned char *)msg +  8);
	x2 = p6 ^ rk2;
	rk3 = sph_dec32le_aligned((const unsigned char *)msg + 12);
	x3 = p7 ^ rk3;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk4 = sph_dec32le_aligned((const unsigned char *)msg + 16);
	x0 ^= rk4;
	rk5 = sph_dec32le_aligned((const unsigned char *)msg + 20);
	x1 ^= rk5;
	rk6 = sph_dec32le_aligned((const unsigned char *)msg + 24);
	x2 ^= rk6;
	rk7 = sph_dec32le_aligned((const unsigned char *)msg + 28);
	x3 ^= rk7;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk8 = sph_dec32le_aligned((const unsigned char *)msg + 32);
	x0 ^= rk8;
	rk9 = sph_dec32le_aligned((const unsigned char *)msg + 36);
	x1 ^= rk9;
	rkA = sph_dec32le_aligned((const unsigned char *)msg + 40);
	x2 ^= rkA;
	rkB = sph_dec32le_aligned((const unsigned char *)msg + 44);
	x3 ^= rkB;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	p0 ^= x0;
	p1 ^= x1;
	p2 ^= x2;
	p3 ^= x3;
	/* round 1 */
	rkC = sph_dec32le_aligned((const unsigned char *)msg + 48);
	x0 = p0 ^ rkC;
	rkD = sph_dec32le_aligned((const unsigned char *)msg + 52);
	x1 = p1 ^ rkD;
	rkE = sph_dec32le_aligned((const unsigned char *)msg + 56);
	x2 = p2 ^ rkE;
	rkF = sph_dec32le_aligned((const unsigned char *)msg + 60);
	x3 = p3 ^ rkF;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rk0, rk1, rk2, rk3);
	rk0 ^= rkC ^ sc->count0;
	rk1 ^= rkD ^ SPH_T32(~sc->count1);
	rk2 ^= rkE;
	rk3 ^= rkF;
	x0 ^= rk0;
	x1 ^= rk1;
	x2 ^= rk2;
	x3 ^= rk3;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rk4, rk5, rk6, rk7);
	rk4 ^= rk0;
	rk5 ^= rk1;
	rk6 ^= rk2;
	rk7 ^= rk3;
	x0 ^= rk4;
	x1 ^= rk5;
	x2 ^= rk6;
	x3 ^= rk7;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	p4 ^= x0;
	p5 ^= x1;
	p6 ^= x2;
	p7 ^= x3;
	/* round 2 */
	KEY_EXPAND_ELT(rk8, rk9, rkA, rkB);
	rk8 ^= rk4;
	rk9 ^= rk5;
	rkA ^= rk6;
	rkB ^= rk7;
	x0 = p4 ^ rk8;
	x1 = p5 ^ rk9;
	x2 = p6 ^ rkA;
	x3 = p7 ^ rkB;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rkC, rkD, rkE, rkF);
	rkC ^= rk8;
	rkD ^= rk9;
	rkE ^= rkA;
	rkF ^= rkB;
	x0 ^= rkC;
	x1 ^= rkD;
	x2 ^= rkE;
	x3 ^= rkF;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk0 ^= rkD;
	x0 ^= rk0;
	rk1 ^= rkE;
	x1 ^= rk1;
	rk2 ^= rkF;
	x2 ^= rk2;
	rk3 ^= rk0;
	x3 ^= rk3;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	p0 ^= x0;
	p1 ^= x1;
	p2 ^= x2;
	p3 ^= x3;
	/* round 3 */
	rk4 ^= rk1;
	x0 = p0 ^ rk4;
	rk5 ^= rk2;
	x1 = p1 ^ rk5;
	rk6 ^= rk3;
	x2 = p2 ^ rk6;
	rk7 ^= rk4;
	x3 = p3 ^ rk7;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk8 ^= rk5;
	x0 ^= rk8;
	rk9 ^= rk6;
	x1 ^= rk9;
	rkA ^= rk7;
	x2 ^= rkA;
	rkB ^= rk8;
	x3 ^= rkB;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rkC ^= rk9;
	x0 ^= rkC;
	rkD ^= rkA;
	x1 ^= rkD;
	rkE ^= rkB;
	x2 ^= rkE;
	rkF ^= rkC;
	x3 ^= rkF;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	p4 ^= x0;
	p5 ^= x1;
	p6 ^= x2;
	p7 ^= x3;
	/* round 4 */
	KEY_EXPAND_ELT(rk0, rk1, rk2, rk3);
	rk0 ^= rkC;
	rk1 ^= rkD;
	rk2 ^= rkE;
	rk3 ^= rkF;
	x0 = p4 ^ rk0;
	x1 = p5 ^ rk1;
	x2 = p6 ^ rk2;
	x3 = p7 ^ rk3;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rk4, rk5, rk6, rk7);
	rk4 ^= rk0;
	rk5 ^= rk1;
	rk6 ^= rk2;
	rk7 ^= rk3;
	x0 ^= rk4;
	x1 ^= rk5;
	x2 ^= rk6;
	x3 ^= rk7;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rk8, rk9, rkA, rkB);
	rk8 ^= rk4;
	rk9 ^= rk5 ^ sc->count1;
	rkA ^= rk6 ^ SPH_T32(~sc->count0);
	rkB ^= rk7;
	x0 ^= rk8;
	x1 ^= rk9;
	x2 ^= rkA;
	x3 ^= rkB;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	p0 ^= x0;
	p1 ^= x1;
	p2 ^= x2;
	p3 ^= x3;
	/* round 5 */
	KEY_EXPAND_ELT(rkC, rkD, rkE, rkF);
	rkC ^= rk8;
	rkD ^= rk9;
	rkE ^= rkA;
	rkF ^= rkB;
	x0 = p0 ^ rkC;
	x1 = p1 ^ rkD;
	x2 = p2 ^ rkE;
	x3 = p3 ^ rkF;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk0 ^= rkD;
	x0 ^= rk0;
	rk1 ^= rkE;
	x1 ^= rk1;
	rk2 ^= rkF;
	x2 ^= rk2;
	rk3 ^= rk0;
	x3 ^= rk3;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk4 ^= rk1;
	x0 ^= rk4;
	rk5 ^= rk2;
	x1 ^= rk5;
	rk6 ^= rk3;
	x2 ^= rk6;
	rk7 ^= rk4;
	x3 ^= rk7;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	p4 ^= x0;
	p5 ^= x1;
	p6 ^= x2;
	p7 ^= x3;
	/* round 6 */
	rk8 ^= rk5;
	x0 = p4 ^ rk8;
	rk9 ^= rk6;
	x1 = p5 ^ rk9;
	rkA ^= rk7;
	x2 = p6 ^ rkA;
	rkB ^= rk8;
	x3 = p7 ^ rkB;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rkC ^= rk9;
	x0 ^= rkC;
	rkD ^= rkA;
	x1 ^= rkD;
	rkE ^= rkB;
	x2 ^= rkE;
	rkF ^= rkC;
	x3 ^= rkF;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rk0, rk1, rk2, rk3);
	rk0 ^= rkC;
	rk1 ^= rkD;
	rk2 ^= rkE;
	rk3 ^= rkF;
	x0 ^= rk0;
	x1 ^= rk1;
	x2 ^= rk2;
	x3 ^= rk3;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	p0 ^= x0;
	p1 ^= x1;
	p2 ^= x2;
	p3 ^= x3;
	/* round 7 */
	KEY_EXPAND_ELT(rk4, rk5, rk6, rk7);
	rk4 ^= rk0;
	rk5 ^= rk1;
	rk6 ^= rk2 ^ sc->count1;
	rk7 ^= rk3 ^ SPH_T32(~sc->count0);
	x0 = p0 ^ rk4;
	x1 = p1 ^ rk5;
	x2 = p2 ^ rk6;
	x3 = p3 ^ rk7;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rk8, rk9, rkA, rkB);
	rk8 ^= rk4;
	rk9 ^= rk5;
	rkA ^= rk6;
	rkB ^= rk7;
	x0 ^= rk8;
	x1 ^= rk9;
	x2 ^= rkA;
	x3 ^= rkB;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rkC, rkD, rkE, rkF);
	rkC ^= rk8;
	rkD ^= rk9;
	rkE ^= rkA;
	rkF ^= rkB;
	x0 ^= rkC;
	x1 ^= rkD;
	x2 ^= rkE;
	x3 ^= rkF;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	p4 ^= x0;
	p5 ^= x1;
	p6 ^= x2;
	p7 ^= x3;
	/* round 8 */
	rk0 ^= rkD;
	x0 = p4 ^ rk0;
	rk1 ^= rkE;
	x1 = p5 ^ rk1;
	rk2 ^= rkF;
	x2 = p6 ^ rk2;
	rk3 ^= rk0;
	x3 = p7 ^ rk3;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk4 ^= rk1;
	x0 ^= rk4;
	rk5 ^= rk2;
	x1 ^= rk5;
	rk6 ^= rk3;
	x2 ^= rk6;
	rk7 ^= rk4;
	x3 ^= rk7;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk8 ^= rk5;
	x0 ^= rk8;
	rk9 ^= rk6;
	x1 ^= rk9;
	rkA ^= rk7;
	x2 ^= rkA;
	rkB ^= rk8;
	x3 ^= rkB;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	p0 ^= x0;
	p1 ^= x1;
	p2 ^= x2;
	p3 ^= x3;
	/* round 9 */
	rkC ^= rk9;
	x0 = p0 ^ rkC;
	rkD ^= rkA;
	x1 = p1 ^ rkD;
	rkE ^= rkB;
	x2 = p2 ^ rkE;
	rkF ^= rkC;
	x3 = p3 ^ rkF;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rk0, rk1, rk2, rk3);
	rk0 ^= rkC;
	rk1 ^= rkD;
	rk2 ^= rkE;
	rk3 ^= rkF;
	x0 ^= rk0;
	x1 ^= rk1;
	x2 ^= rk2;
	x3 ^= rk3;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rk4, rk5, rk6, rk7);
	rk4 ^= rk0;
	rk5 ^= rk1;
	rk6 ^= rk2;
	rk7 ^= rk3;
	x0 ^= rk4;
	x1 ^= rk5;
	x2 ^= rk6;
	x3 ^= rk7;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	p4 ^= x0;
	p5 ^= x1;
	p6 ^= x2;
	p7 ^= x3;
	/* round 10 */
	KEY_EXPAND_ELT(rk8, rk9, rkA, rkB);
	rk8 ^= rk4;
	rk9 ^= rk5;
	rkA ^= rk6;
	rkB ^= rk7;
	x0 = p4 ^ rk8;
	x1 = p5 ^ rk9;
	x2 = p6 ^ rkA;
	x3 = p7 ^ rkB;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rkC, rkD, rkE, rkF);
	rkC ^= rk8 ^ sc->count0;
	rkD ^= rk9;
	rkE ^= rkA;
	rkF ^= rkB ^ SPH_T32(~sc->count1);
	x0 ^= rkC;
	x1 ^= rkD;
	x2 ^= rkE;
	x3 ^= rkF;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk0 ^= rkD;
	x0 ^= rk0;
	rk1 ^= rkE;
	x1 ^= rk1;
	rk2 ^= rkF;
	x2 ^= rk2;
	rk3 ^= rk0;
	x3 ^= rk3;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	p0 ^= x0;
	p1 ^= x1;
	p2 ^= x2;
	p3 ^= x3;
	/* round 11 */
	rk4 ^= rk1;
	x0 = p0 ^ rk4;
	rk5 ^= rk2;
	x1 = p1 ^ rk5;
	rk6 ^= rk3;
	x2 = p2 ^ rk6;
	rk7 ^= rk4;
	x3 = p3 ^ rk7;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk8 ^= rk5;
	x0 ^= rk8;
	rk9 ^= rk6;
	x1 ^= rk9;
	rkA ^= rk7;
	x2 ^= rkA;
	rkB ^= rk8;
	x3 ^= rkB;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rkC ^= rk9;
	x0 ^= rkC;
	rkD ^= rkA;
	x1 ^= rkD;
	rkE ^= rkB;
	x2 ^= rkE;
	rkF ^= rkC;
	x3 ^= rkF;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	p4 ^= x0;
	p5 ^= x1;
	p6 ^= x2;
	p7 ^= x3;
	sc->h[0x0] ^= p0;
	sc->h[0x1] ^= p1;
	sc->h[0x2] ^= p2;
	sc->h[0x3] ^= p3;
	sc->h[0x4] ^= p4;
	sc->h[0x5] ^= p5;
	sc->h[0x6] ^= p6;
	sc->h[0x7] ^= p7;
}

#endif

#if SPH_SMALL_FOOTPRINT_SHAVITE

/*
 * This function assumes that "msg" is aligned for 32-bit access.
 */
static void
c512(sph_shavite_big_context *sc, const void *msg)
{
	sph_u32 p0, p1, p2, p3, p4, p5, p6, p7;
	sph_u32 p8, p9, pA, pB, pC, pD, pE, pF;
	sph_u32 rk[448];
	size_t u;
	int r, s;

#if SPH_LITTLE_ENDIAN
	memcpy(rk, msg, 128);
#else
	for (u = 0; u < 32; u += 4) {
		rk[u + 0] = sph_dec32le_aligned(
			(const unsigned char *)msg + (u << 2) +  0);
		rk[u + 1] = sph_dec32le_aligned(
			(const unsigned char *)msg + (u << 2) +  4);
		rk[u + 2] = sph_dec32le_aligned(
			(const unsigned char *)msg + (u << 2) +  8);
		rk[u + 3] = sph_dec32le_aligned(
			(const unsigned char *)msg + (u << 2) + 12);
	}
#endif
	u = 32;
	for (;;) {
		for (s = 0; s < 4; s ++) {
			sph_u32 x0, x1, x2, x3;

			x0 = rk[u - 31];
			x1 = rk[u - 30];
			x2 = rk[u - 29];
			x3 = rk[u - 32];
			AES_ROUND_NOKEY(x0, x1, x2, x3);
			rk[u + 0] = x0 ^ rk[u - 4];
			rk[u + 1] = x1 ^ rk[u - 3];
			rk[u + 2] = x2 ^ rk[u - 2];
			rk[u + 3] = x3 ^ rk[u - 1];
			if (u == 32) {
				rk[ 32] ^= sc->count0;
				rk[ 33] ^= sc->count1;
				rk[ 34] ^= sc->count2;
				rk[ 35] ^= SPH_T32(~sc->count3);
			} else if (u == 440) {
				rk[440] ^= sc->count1;
				rk[441] ^= sc->count0;
				rk[442] ^= sc->count3;
				rk[443] ^= SPH_T32(~sc->count2);
			}
			u += 4;

			x0 = rk[u - 31];
			x1 = rk[u - 30];
			x2 = rk[u - 29];
			x3 = rk[u - 32];
			AES_ROUND_NOKEY(x0, x1, x2, x3);
			rk[u + 0] = x0 ^ rk[u - 4];
			rk[u + 1] = x1 ^ rk[u - 3];
			rk[u + 2] = x2 ^ rk[u - 2];
			rk[u + 3] = x3 ^ rk[u - 1];
			if (u == 164) {
				rk[164] ^= sc->count3;
				rk[165] ^= sc->count2;
				rk[166] ^= sc->count1;
				rk[167] ^= SPH_T32(~sc->count0);
			} else if (u == 316) {
				rk[316] ^= sc->count2;
				rk[317] ^= sc->count3;
				rk[318] ^= sc->count0;
				rk[319] ^= SPH_T32(~sc->count1);
			}
			u += 4;
		}
		if (u == 448)
			break;
		for (s = 0; s < 8; s ++) {
			rk[u + 0] = rk[u - 32] ^ rk[u - 7];
			rk[u + 1] = rk[u - 31] ^ rk[u - 6];
			rk[u + 2] = rk[u - 30] ^ rk[u - 5];
			rk[u + 3] = rk[u - 29] ^ rk[u - 4];
			u += 4;
		}
	}

	p0 = sc->h[0x0];
	p1 = sc->h[0x1];
	p2 = sc->h[0x2];
	p3 = sc->h[0x3];
	p4 = sc->h[0x4];
	p5 = sc->h[0x5];
	p6 = sc->h[0x6];
	p7 = sc->h[0x7];
	p8 = sc->h[0x8];
	p9 = sc->h[0x9];
	pA = sc->h[0xA];
	pB = sc->h[0xB];
	pC = sc->h[0xC];
	pD = sc->h[0xD];
	pE = sc->h[0xE];
	pF = sc->h[0xF];
	u = 0;
	for (r = 0; r < 14; r ++) {
#define C512_ELT(l0, l1, l2, l3, r0, r1, r2, r3)   do { \
		sph_u32 x0, x1, x2, x3; \
		x0 = r0 ^ rk[u ++]; \
		x1 = r1 ^ rk[u ++]; \
		x2 = r2 ^ rk[u ++]; \
		x3 = r3 ^ rk[u ++]; \
		AES_ROUND_NOKEY(x0, x1, x2, x3); \
		x0 ^= rk[u ++]; \
		x1 ^= rk[u ++]; \
		x2 ^= rk[u ++]; \
		x3 ^= rk[u ++]; \
		AES_ROUND_NOKEY(x0, x1, x2, x3); \
		x0 ^= rk[u ++]; \
		x1 ^= rk[u ++]; \
		x2 ^= rk[u ++]; \
		x3 ^= rk[u ++]; \
		AES_ROUND_NOKEY(x0, x1, x2, x3); \
		x0 ^= rk[u ++]; \
		x1 ^= rk[u ++]; \
		x2 ^= rk[u ++]; \
		x3 ^= rk[u ++]; \
		AES_ROUND_NOKEY(x0, x1, x2, x3); \
		l0 ^= x0; \
		l1 ^= x1; \
		l2 ^= x2; \
		l3 ^= x3; \
	} while (0)

#define WROT(a, b, c, d)   do { \
		sph_u32 t = d; \
		d = c; \
		c = b; \
		b = a; \
		a = t; \
	} while (0)

		C512_ELT(p0, p1, p2, p3, p4, p5, p6, p7);
		C512_ELT(p8, p9, pA, pB, pC, pD, pE, pF);

		WROT(p0, p4, p8, pC);
		WROT(p1, p5, p9, pD);
		WROT(p2, p6, pA, pE);
		WROT(p3, p7, pB, pF);

#undef C512_ELT
#undef WROT
	}
	sc->h[0x0] ^= p0;
	sc->h[0x1] ^= p1;
	sc->h[0x2] ^= p2;
	sc->h[0x3] ^= p3;
	sc->h[0x4] ^= p4;
	sc->h[0x5] ^= p5;
	sc->h[0x6] ^= p6;
	sc->h[0x7] ^= p7;
	sc->h[0x8] ^= p8;
	sc->h[0x9] ^= p9;
	sc->h[0xA] ^= pA;
	sc->h[0xB] ^= pB;
	sc->h[0xC] ^= pC;
	sc->h[0xD] ^= pD;
	sc->h[0xE] ^= pE;
	sc->h[0xF] ^= pF;
}

#else

/*
 * This function assumes that "msg" is aligned for 32-bit access.
 */
static void
c512(sph_shavite_big_context *sc, const void *msg)
{
	sph_u32 p0, p1, p2, p3, p4, p5, p6, p7;
	sph_u32 p8, p9, pA, pB, pC, pD, pE, pF;
	sph_u32 x0, x1, x2, x3;
	sph_u32 rk00, rk01, rk02, rk03, rk04, rk05, rk06, rk07;
	sph_u32 rk08, rk09, rk0A, rk0B, rk0C, rk0D, rk0E, rk0F;
	sph_u32 rk10, rk11, rk12, rk13, rk14, rk15, rk16, rk17;
	sph_u32 rk18, rk19, rk1A, rk1B, rk1C, rk1D, rk1E, rk1F;
	int r;

	p0 = sc->h[0x0];
	p1 = sc->h[0x1];
	p2 = sc->h[0x2];
	p3 = sc->h[0x3];
	p4 = sc->h[0x4];
	p5 = sc->h[0x5];
	p6 = sc->h[0x6];
	p7 = sc->h[0x7];
	p8 = sc->h[0x8];
	p9 = sc->h[0x9];
	pA = sc->h[0xA];
	pB = sc->h[0xB];
	pC = sc->h[0xC];
	pD = sc->h[0xD];
	pE = sc->h[0xE];
	pF = sc->h[0xF];
	/* round 0 */
	rk00 = sph_dec32le_aligned((const unsigned char *)msg +   0);
	x0 = p4 ^ rk00;
	rk01 = sph_dec32le_aligned((const unsigned char *)msg +   4);
	x1 = p5 ^ rk01;
	rk02 = sph_dec32le_aligned((const unsigned char *)msg +   8);
	x2 = p6 ^ rk02;
	rk03 = sph_dec32le_aligned((const unsigned char *)msg +  12);
	x3 = p7 ^ rk03;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk04 = sph_dec32le_aligned((const unsigned char *)msg +  16);
	x0 ^= rk04;
	rk05 = sph_dec32le_aligned((const unsigned char *)msg +  20);
	x1 ^= rk05;
	rk06 = sph_dec32le_aligned((const unsigned char *)msg +  24);
	x2 ^= rk06;
	rk07 = sph_dec32le_aligned((const unsigned char *)msg +  28);
	x3 ^= rk07;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk08 = sph_dec32le_aligned((const unsigned char *)msg +  32);
	x0 ^= rk08;
	rk09 = sph_dec32le_aligned((const unsigned char *)msg +  36);
	x1 ^= rk09;
	rk0A = sph_dec32le_aligned((const unsigned char *)msg +  40);
	x2 ^= rk0A;
	rk0B = sph_dec32le_aligned((const unsigned char *)msg +  44);
	x3 ^= rk0B;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk0C = sph_dec32le_aligned((const unsigned char *)msg +  48);
	x0 ^= rk0C;
	rk0D = sph_dec32le_aligned((const unsigned char *)msg +  52);
	x1 ^= rk0D;
	rk0E = sph_dec32le_aligned((const unsigned char *)msg +  56);
	x2 ^= rk0E;
	rk0F = sph_dec32le_aligned((const unsigned char *)msg +  60);
	x3 ^= rk0F;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	p0 ^= x0;
	p1 ^= x1;
	p2 ^= x2;
	p3 ^= x3;
	rk10 = sph_dec32le_aligned((const unsigned char *)msg +  64);
	x0 = pC ^ rk10;
	rk11 = sph_dec32le_aligned((const unsigned char *)msg +  68);
	x1 = pD ^ rk11;
	rk12 = sph_dec32le_aligned((const unsigned char *)msg +  72);
	x2 = pE ^ rk12;
	rk13 = sph_dec32le_aligned((const unsigned char *)msg +  76);
	x3 = pF ^ rk13;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk14 = sph_dec32le_aligned((const unsigned char *)msg +  80);
	x0 ^= rk14;
	rk15 = sph_dec32le_aligned((const unsigned char *)msg +  84);
	x1 ^= rk15;
	rk16 = sph_dec32le_aligned((const unsigned char *)msg +  88);
	x2 ^= rk16;
	rk17 = sph_dec32le_aligned((const unsigned char *)msg +  92);
	x3 ^= rk17;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk18 = sph_dec32le_aligned((const unsigned char *)msg +  96);
	x0 ^= rk18;
	rk19 = sph_dec32le_aligned((const unsigned char *)msg + 100);
	x1 ^= rk19;
	rk1A = sph_dec32le_aligned((const unsigned char *)msg + 104);
	x2 ^= rk1A;
	rk1B = sph_dec32le_aligned((const unsigned char *)msg + 108);
	x3 ^= rk1B;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	rk1C = sph_dec32le_aligned((const unsigned char *)msg + 112);
	x0 ^= rk1C;
	rk1D = sph_dec32le_aligned((const unsigned char *)msg + 116);
	x1 ^= rk1D;
	rk1E = sph_dec32le_aligned((const unsigned char *)msg + 120);
	x2 ^= rk1E;
	rk1F = sph_dec32le_aligned((const unsigned char *)msg + 124);
	x3 ^= rk1F;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	p8 ^= x0;
	p9 ^= x1;
	pA ^= x2;
	pB ^= x3;

	for (r = 0; r < 3; r ++) {
		/* round 1, 5, 9 */
		KEY_EXPAND_ELT(rk00, rk01, rk02, rk03);
		rk00 ^= rk1C;
		rk01 ^= rk1D;
		rk02 ^= rk1E;
		rk03 ^= rk1F;
		if (r == 0) {
			rk00 ^= sc->count0;
			rk01 ^= sc->count1;
			rk02 ^= sc->count2;
			rk03 ^= SPH_T32(~sc->count3);
		}
		x0 = p0 ^ rk00;
		x1 = p1 ^ rk01;
		x2 = p2 ^ rk02;
		x3 = p3 ^ rk03;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		KEY_EXPAND_ELT(rk04, rk05, rk06, rk07);
		rk04 ^= rk00;
		rk05 ^= rk01;
		rk06 ^= rk02;
		rk07 ^= rk03;
		if (r == 1) {
			rk04 ^= sc->count3;
			rk05 ^= sc->count2;
			rk06 ^= sc->count1;
			rk07 ^= SPH_T32(~sc->count0);
		}
		x0 ^= rk04;
		x1 ^= rk05;
		x2 ^= rk06;
		x3 ^= rk07;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		KEY_EXPAND_ELT(rk08, rk09, rk0A, rk0B);
		rk08 ^= rk04;
		rk09 ^= rk05;
		rk0A ^= rk06;
		rk0B ^= rk07;
		x0 ^= rk08;
		x1 ^= rk09;
		x2 ^= rk0A;
		x3 ^= rk0B;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		KEY_EXPAND_ELT(rk0C, rk0D, rk0E, rk0F);
		rk0C ^= rk08;
		rk0D ^= rk09;
		rk0E ^= rk0A;
		rk0F ^= rk0B;
		x0 ^= rk0C;
		x1 ^= rk0D;
		x2 ^= rk0E;
		x3 ^= rk0F;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		pC ^= x0;
		pD ^= x1;
		pE ^= x2;
		pF ^= x3;
		KEY_EXPAND_ELT(rk10, rk11, rk12, rk13);
		rk10 ^= rk0C;
		rk11 ^= rk0D;
		rk12 ^= rk0E;
		rk13 ^= rk0F;
		x0 = p8 ^ rk10;
		x1 = p9 ^ rk11;
		x2 = pA ^ rk12;
		x3 = pB ^ rk13;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		KEY_EXPAND_ELT(rk14, rk15, rk16, rk17);
		rk14 ^= rk10;
		rk15 ^= rk11;
		rk16 ^= rk12;
		rk17 ^= rk13;
		x0 ^= rk14;
		x1 ^= rk15;
		x2 ^= rk16;
		x3 ^= rk17;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		KEY_EXPAND_ELT(rk18, rk19, rk1A, rk1B);
		rk18 ^= rk14;
		rk19 ^= rk15;
		rk1A ^= rk16;
		rk1B ^= rk17;
		x0 ^= rk18;
		x1 ^= rk19;
		x2 ^= rk1A;
		x3 ^= rk1B;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		KEY_EXPAND_ELT(rk1C, rk1D, rk1E, rk1F);
		rk1C ^= rk18;
		rk1D ^= rk19;
		rk1E ^= rk1A;
		rk1F ^= rk1B;
		if (r == 2) {
			rk1C ^= sc->count2;
			rk1D ^= sc->count3;
			rk1E ^= sc->count0;
			rk1F ^= SPH_T32(~sc->count1);
		}
		x0 ^= rk1C;
		x1 ^= rk1D;
		x2 ^= rk1E;
		x3 ^= rk1F;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		p4 ^= x0;
		p5 ^= x1;
		p6 ^= x2;
		p7 ^= x3;
		/* round 2, 6, 10 */
		rk00 ^= rk19;
		x0 = pC ^ rk00;
		rk01 ^= rk1A;
		x1 = pD ^ rk01;
		rk02 ^= rk1B;
		x2 = pE ^ rk02;
		rk03 ^= rk1C;
		x3 = pF ^ rk03;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		rk04 ^= rk1D;
		x0 ^= rk04;
		rk05 ^= rk1E;
		x1 ^= rk05;
		rk06 ^= rk1F;
		x2 ^= rk06;
		rk07 ^= rk00;
		x3 ^= rk07;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		rk08 ^= rk01;
		x0 ^= rk08;
		rk09 ^= rk02;
		x1 ^= rk09;
		rk0A ^= rk03;
		x2 ^= rk0A;
		rk0B ^= rk04;
		x3 ^= rk0B;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		rk0C ^= rk05;
		x0 ^= rk0C;
		rk0D ^= rk06;
		x1 ^= rk0D;
		rk0E ^= rk07;
		x2 ^= rk0E;
		rk0F ^= rk08;
		x3 ^= rk0F;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		p8 ^= x0;
		p9 ^= x1;
		pA ^= x2;
		pB ^= x3;
		rk10 ^= rk09;
		x0 = p4 ^ rk10;
		rk11 ^= rk0A;
		x1 = p5 ^ rk11;
		rk12 ^= rk0B;
		x2 = p6 ^ rk12;
		rk13 ^= rk0C;
		x3 = p7 ^ rk13;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		rk14 ^= rk0D;
		x0 ^= rk14;
		rk15 ^= rk0E;
		x1 ^= rk15;
		rk16 ^= rk0F;
		x2 ^= rk16;
		rk17 ^= rk10;
		x3 ^= rk17;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		rk18 ^= rk11;
		x0 ^= rk18;
		rk19 ^= rk12;
		x1 ^= rk19;
		rk1A ^= rk13;
		x2 ^= rk1A;
		rk1B ^= rk14;
		x3 ^= rk1B;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		rk1C ^= rk15;
		x0 ^= rk1C;
		rk1D ^= rk16;
		x1 ^= rk1D;
		rk1E ^= rk17;
		x2 ^= rk1E;
		rk1F ^= rk18;
		x3 ^= rk1F;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		p0 ^= x0;
		p1 ^= x1;
		p2 ^= x2;
		p3 ^= x3;
		/* round 3, 7, 11 */
		KEY_EXPAND_ELT(rk00, rk01, rk02, rk03);
		rk00 ^= rk1C;
		rk01 ^= rk1D;
		rk02 ^= rk1E;
		rk03 ^= rk1F;
		x0 = p8 ^ rk00;
		x1 = p9 ^ rk01;
		x2 = pA ^ rk02;
		x3 = pB ^ rk03;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		KEY_EXPAND_ELT(rk04, rk05, rk06, rk07);
		rk04 ^= rk00;
		rk05 ^= rk01;
		rk06 ^= rk02;
		rk07 ^= rk03;
		x0 ^= rk04;
		x1 ^= rk05;
		x2 ^= rk06;
		x3 ^= rk07;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		KEY_EXPAND_ELT(rk08, rk09, rk0A, rk0B);
		rk08 ^= rk04;
		rk09 ^= rk05;
		rk0A ^= rk06;
		rk0B ^= rk07;
		x0 ^= rk08;
		x1 ^= rk09;
		x2 ^= rk0A;
		x3 ^= rk0B;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		KEY_EXPAND_ELT(rk0C, rk0D, rk0E, rk0F);
		rk0C ^= rk08;
		rk0D ^= rk09;
		rk0E ^= rk0A;
		rk0F ^= rk0B;
		x0 ^= rk0C;
		x1 ^= rk0D;
		x2 ^= rk0E;
		x3 ^= rk0F;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		p4 ^= x0;
		p5 ^= x1;
		p6 ^= x2;
		p7 ^= x3;
		KEY_EXPAND_ELT(rk10, rk11, rk12, rk13);
		rk10 ^= rk0C;
		rk11 ^= rk0D;
		rk12 ^= rk0E;
		rk13 ^= rk0F;
		x0 = p0 ^ rk10;
		x1 = p1 ^ rk11;
		x2 = p2 ^ rk12;
		x3 = p3 ^ rk13;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		KEY_EXPAND_ELT(rk14, rk15, rk16, rk17);
		rk14 ^= rk10;
		rk15 ^= rk11;
		rk16 ^= rk12;
		rk17 ^= rk13;
		x0 ^= rk14;
		x1 ^= rk15;
		x2 ^= rk16;
		x3 ^= rk17;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		KEY_EXPAND_ELT(rk18, rk19, rk1A, rk1B);
		rk18 ^= rk14;
		rk19 ^= rk15;
		rk1A ^= rk16;
		rk1B ^= rk17;
		x0 ^= rk18;
		x1 ^= rk19;
		x2 ^= rk1A;
		x3 ^= rk1B;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		KEY_EXPAND_ELT(rk1C, rk1D, rk1E, rk1F);
		rk1C ^= rk18;
		rk1D ^= rk19;
		rk1E ^= rk1A;
		rk1F ^= rk1B;
		x0 ^= rk1C;
		x1 ^= rk1D;
		x2 ^= rk1E;
		x3 ^= rk1F;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		pC ^= x0;
		pD ^= x1;
		pE ^= x2;
		pF ^= x3;
		/* round 4, 8, 12 */
		rk00 ^= rk19;
		x0 = p4 ^ rk00;
		rk01 ^= rk1A;
		x1 = p5 ^ rk01;
		rk02 ^= rk1B;
		x2 = p6 ^ rk02;
		rk03 ^= rk1C;
		x3 = p7 ^ rk03;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		rk04 ^= rk1D;
		x0 ^= rk04;
		rk05 ^= rk1E;
		x1 ^= rk05;
		rk06 ^= rk1F;
		x2 ^= rk06;
		rk07 ^= rk00;
		x3 ^= rk07;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		rk08 ^= rk01;
		x0 ^= rk08;
		rk09 ^= rk02;
		x1 ^= rk09;
		rk0A ^= rk03;
		x2 ^= rk0A;
		rk0B ^= rk04;
		x3 ^= rk0B;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		rk0C ^= rk05;
		x0 ^= rk0C;
		rk0D ^= rk06;
		x1 ^= rk0D;
		rk0E ^= rk07;
		x2 ^= rk0E;
		rk0F ^= rk08;
		x3 ^= rk0F;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		p0 ^= x0;
		p1 ^= x1;
		p2 ^= x2;
		p3 ^= x3;
		rk10 ^= rk09;
		x0 = pC ^ rk10;
		rk11 ^= rk0A;
		x1 = pD ^ rk11;
		rk12 ^= rk0B;
		x2 = pE ^ rk12;
		rk13 ^= rk0C;
		x3 = pF ^ rk13;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		rk14 ^= rk0D;
		x0 ^= rk14;
		rk15 ^= rk0E;
		x1 ^= rk15;
		rk16 ^= rk0F;
		x2 ^= rk16;
		rk17 ^= rk10;
		x3 ^= rk17;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		rk18 ^= rk11;
		x0 ^= rk18;
		rk19 ^= rk12;
		x1 ^= rk19;
		rk1A ^= rk13;
		x2 ^= rk1A;
		rk1B ^= rk14;
		x3 ^= rk1B;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		rk1C ^= rk15;
		x0 ^= rk1C;
		rk1D ^= rk16;
		x1 ^= rk1D;
		rk1E ^= rk17;
		x2 ^= rk1E;
		rk1F ^= rk18;
		x3 ^= rk1F;
		AES_ROUND_NOKEY(x0, x1, x2, x3);
		p8 ^= x0;
		p9 ^= x1;
		pA ^= x2;
		pB ^= x3;
	}
	/* round 13 */
	KEY_EXPAND_ELT(rk00, rk01, rk02, rk03);
	rk00 ^= rk1C;
	rk01 ^= rk1D;
	rk02 ^= rk1E;
	rk03 ^= rk1F;
	x0 = p0 ^ rk00;
	x1 = p1 ^ rk01;
	x2 = p2 ^ rk02;
	x3 = p3 ^ rk03;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rk04, rk05, rk06, rk07);
	rk04 ^= rk00;
	rk05 ^= rk01;
	rk06 ^= rk02;
	rk07 ^= rk03;
	x0 ^= rk04;
	x1 ^= rk05;
	x2 ^= rk06;
	x3 ^= rk07;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rk08, rk09, rk0A, rk0B);
	rk08 ^= rk04;
	rk09 ^= rk05;
	rk0A ^= rk06;
	rk0B ^= rk07;
	x0 ^= rk08;
	x1 ^= rk09;
	x2 ^= rk0A;
	x3 ^= rk0B;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rk0C, rk0D, rk0E, rk0F);
	rk0C ^= rk08;
	rk0D ^= rk09;
	rk0E ^= rk0A;
	rk0F ^= rk0B;
	x0 ^= rk0C;
	x1 ^= rk0D;
	x2 ^= rk0E;
	x3 ^= rk0F;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	pC ^= x0;
	pD ^= x1;
	pE ^= x2;
	pF ^= x3;
	KEY_EXPAND_ELT(rk10, rk11, rk12, rk13);
	rk10 ^= rk0C;
	rk11 ^= rk0D;
	rk12 ^= rk0E;
	rk13 ^= rk0F;
	x0 = p8 ^ rk10;
	x1 = p9 ^ rk11;
	x2 = pA ^ rk12;
	x3 = pB ^ rk13;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rk14, rk15, rk16, rk17);
	rk14 ^= rk10;
	rk15 ^= rk11;
	rk16 ^= rk12;
	rk17 ^= rk13;
	x0 ^= rk14;
	x1 ^= rk15;
	x2 ^= rk16;
	x3 ^= rk17;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rk18, rk19, rk1A, rk1B);
	rk18 ^= rk14 ^ sc->count1;
	rk19 ^= rk15 ^ sc->count0;
	rk1A ^= rk16 ^ sc->count3;
	rk1B ^= rk17 ^ SPH_T32(~sc->count2);
	x0 ^= rk18;
	x1 ^= rk19;
	x2 ^= rk1A;
	x3 ^= rk1B;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	KEY_EXPAND_ELT(rk1C, rk1D, rk1E, rk1F);
	rk1C ^= rk18;
	rk1D ^= rk19;
	rk1E ^= rk1A;
	rk1F ^= rk1B;
	x0 ^= rk1C;
	x1 ^= rk1D;
	x2 ^= rk1E;
	x3 ^= rk1F;
	AES_ROUND_NOKEY(x0, x1, x2, x3);
	p4 ^= x0;
	p5 ^= x1;
	p6 ^= x2;
	p7 ^= x3;
	sc->h[0x0] ^= p8;
	sc->h[0x1] ^= p9;
	sc->h[0x2] ^= pA;
	sc->h[0x3] ^= pB;
	sc->h[0x4] ^= pC;
	sc->h[0x5] ^= pD;
	sc->h[0x6] ^= pE;
	sc->h[0x7] ^= pF;
	sc->h[0x8] ^= p0;
	sc->h[0x9] ^= p1;
	sc->h[0xA] ^= p2;
	sc->h[0xB] ^= p3;
	sc->h[0xC] ^= p4;
	sc->h[0xD] ^= p5;
	sc->h[0xE] ^= p6;
	sc->h[0xF] ^= p7;
}

#endif

static void
shavite_small_init(sph_shavite_small_context *sc, const sph_u32 *iv)
{
	memcpy(sc->h, iv, sizeof sc->h);
	sc->ptr = 0;
	sc->count0 = 0;
	sc->count1 = 0;
}

static void
shavite_small_core(sph_shavite_small_context *sc, const void *data, size_t len)
{
	unsigned char *buf;
	size_t ptr;

	buf = sc->buf;
	ptr = sc->ptr;
	while (len > 0) {
		size_t clen;

		clen = (sizeof sc->buf) - ptr;
		if (clen > len)
			clen = len;
		memcpy(buf + ptr, data, clen);
		data = (const unsigned char *)data + clen;
		ptr += clen;
		len -= clen;
		if (ptr == sizeof sc->buf) {
			if ((sc->count0 = SPH_T32(sc->count0 + 512)) == 0)
				sc->count1 = SPH_T32(sc->count1 + 1);
			c256(sc, buf);
			ptr = 0;
		}
	}
	sc->ptr = ptr;
}

static void
shavite_small_close(sph_shavite_small_context *sc,
	unsigned ub, unsigned n, void *dst, size_t out_size_w32)
{
	unsigned char *buf;
	size_t ptr, u;
	unsigned z;
	sph_u32 count0, count1;

	buf = sc->buf;
	ptr = sc->ptr;
	count0 = (sc->count0 += (ptr << 3) + n);
	count1 = sc->count1;
	z = 0x80 >> n;
	z = ((ub & -z) | z) & 0xFF;
	if (ptr == 0 && n == 0) {
		buf[0] = 0x80;
		memset(buf + 1, 0, 53);
		sc->count0 = sc->count1 = 0;
	} else if (ptr < 54) {
		buf[ptr ++] = z;
		memset(buf + ptr, 0, 54 - ptr);
	} else {
		buf[ptr ++] = z;
		memset(buf + ptr, 0, 64 - ptr);
		c256(sc, buf);
		memset(buf, 0, 54);
		sc->count0 = sc->count1 = 0;
	}
	sph_enc32le(buf + 54, count0);
	sph_enc32le(buf + 58, count1);
	buf[62] = out_size_w32 << 5;
	buf[63] = out_size_w32 >> 3;
	c256(sc, buf);
	for (u = 0; u < out_size_w32; u ++)
		sph_enc32le((unsigned char *)dst + (u << 2), sc->h[u]);
}

static void
shavite_big_init(sph_shavite_big_context *sc, const sph_u32 *iv)
{
	memcpy(sc->h, iv, sizeof sc->h);
	sc->ptr = 0;
	sc->count0 = 0;
	sc->count1 = 0;
	sc->count2 = 0;
	sc->count3 = 0;
}

static void
shavite_big_core(sph_shavite_big_context *sc, const void *data, size_t len)
{
	unsigned char *buf;
	size_t ptr;

	buf = sc->buf;
	ptr = sc->ptr;
	while (len > 0) {
		size_t clen;

		clen = (sizeof sc->buf) - ptr;
		if (clen > len)
			clen = len;
		memcpy(buf + ptr, data, clen);
		data = (const unsigned char *)data + clen;
		ptr += clen;
		len -= clen;
		if (ptr == sizeof sc->buf) {
			if ((sc->count0 = SPH_T32(sc->count0 + 1024)) == 0) {
				sc->count1 = SPH_T32(sc->count1 + 1);
				if (sc->count1 == 0) {
					sc->count2 = SPH_T32(sc->count2 + 1);
					if (sc->count2 == 0) {
						sc->count3 = SPH_T32(
							sc->count3 + 1);
					}
				}
			}
			c512(sc, buf);
			ptr = 0;
		}
	}
	sc->ptr = ptr;
}

static void
shavite_big_close(sph_shavite_big_context *sc,
	unsigned ub, unsigned n, void *dst, size_t out_size_w32)
{
	unsigned char *buf;
	size_t ptr, u;
	unsigned z;
	sph_u32 count0, count1, count2, count3;

	buf = sc->buf;
	ptr = sc->ptr;
	count0 = (sc->count0 += (ptr << 3) + n);
	count1 = sc->count1;
	count2 = sc->count2;
	count3 = sc->count3;
	z = 0x80 >> n;
	z = ((ub & -z) | z) & 0xFF;
	if (ptr == 0 && n == 0) {
		buf[0] = 0x80;
		memset(buf + 1, 0, 109);
		sc->count0 = sc->count1 = sc->count2 = sc->count3 = 0;
	} else if (ptr < 110) {
		buf[ptr ++] = z;
		memset(buf + ptr, 0, 110 - ptr);
	} else {
		buf[ptr ++] = z;
		memset(buf + ptr, 0, 128 - ptr);
		c512(sc, buf);
		memset(buf, 0, 110);
		sc->count0 = sc->count1 = sc->count2 = sc->count3 = 0;
	}
	sph_enc32le(buf + 110, count0);
	sph_enc32le(buf + 114, count1);
	sph_enc32le(buf + 118, count2);
	sph_enc32le(buf + 122, count3);
	buf[126] = out_size_w32 << 5;
	buf[127] = out_size_w32 >> 3;
	c512(sc, buf);
	for (u = 0; u < out_size_w32; u ++)
		sph_enc32le((unsigned char *)dst + (u << 2), sc->h[u]);
}

/* see sph_shavite.h */
void
sph_shavite224_init(void *cc)
{
	shavite_small_init(cc, IV224);
}

/* see sph_shavite.h */
void
sph_shavite224(void *cc, const void *data, size_t len)
{
	shavite_small_core(cc, data, len);
}

/* see sph_shavite.h */
void
sph_shavite224_close(void *cc, void *dst)
{
	shavite_small_close(cc, 0, 0, dst, 7);
	shavite_small_init(cc, IV224);
}

/* see sph_shavite.h */
void
sph_shavite224_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	shavite_small_close(cc, ub, n, dst, 7);
	shavite_small_init(cc, IV224);
}

/* see sph_shavite.h */
void
sph_shavite256_init(void *cc)
{
	shavite_small_init(cc, IV256);
}

/* see sph_shavite.h */
void
sph_shavite256(void *cc, const void *data, size_t len)
{
	shavite_small_core(cc, data, len);
}

/* see sph_shavite.h */
void
sph_shavite256_close(void *cc, void *dst)
{
	shavite_small_close(cc, 0, 0, dst, 8);
	shavite_small_init(cc, IV256);
}

/* see sph_shavite.h */
void
sph_shavite256_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	shavite_small_close(cc, ub, n, dst, 8);
	shavite_small_init(cc, IV256);
}

/* see sph_shavite.h */
void
sph_shavite384_init(void *cc)
{
	shavite_big_init(cc, IV384);
}

/* see sph_shavite.h */
void
sph_shavite384(void *cc, const void *data, size_t len)
{
	shavite_big_core(cc, data, len);
}

/* see sph_shavite.h */
void
sph_shavite384_close(void *cc, void *dst)
{
	shavite_big_close(cc, 0, 0, dst, 12);
	shavite_big_init(cc, IV384);
}

/* see sph_shavite.h */
void
sph_shavite384_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	shavite_big_close(cc, ub, n, dst, 12);
	shavite_big_init(cc, IV384);
}

/* see sph_shavite.h */
void
sph_shavite512_init(void *cc)
{
	shavite_big_init(cc, IV512);
}

/* see sph_shavite.h */
void
sph_shavite512(void *cc, const void *data, size_t len)
{
	shavite_big_core(cc, data, len);
}

/* see sph_shavite.h */
void
sph_shavite512_close(void *cc, void *dst)
{
	shavite_big_close(cc, 0, 0, dst, 16);
	shavite_big_init(cc, IV512);
}

/* see sph_shavite.h */
void
sph_shavite512_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	shavite_big_close(cc, ub, n, dst, 16);
	shavite_big_init(cc, IV512);
}

#ifdef __cplusplus
}
#endif