#include "pke.h"
#include "param.h"
#include "encode.h"
#include "matrix.h"
#include "sample.h"
#include "fips202.h"
#include "random.h"
#include <stdlib.h>
#include <string.h>
void scloudplus_pkekeygen(uint8_t *pk, uint8_t *sk)
{
	uint16_t *S =
		(uint16_t *)malloc(sizeof(uint16_t) * scloudplus_n * scloudplus_nbar);
	uint16_t *E =
		(uint16_t *)malloc(sizeof(uint16_t) * scloudplus_m * scloudplus_nbar);
	uint16_t *B =
		(uint16_t *)malloc(sizeof(uint16_t) * scloudplus_m * scloudplus_nbar);
	uint8_t alpha[32], seed[80];
	uint8_t *seedA = seed;
	uint8_t *r1 = seed + 16;
	uint8_t *r2 = seed + 48;
	randombytes(alpha, 32);
	scloudplus_F(seed, 80, alpha, 32);
	scloudplus_samplepsi(r1, S);
	scloudplus_sampleeta1(r2, E);
	scloudplus_mul_add_as_e(seedA, S, E, B);
	scloudplus_packpk(B, pk);
	memcpy(pk + scloudplus_pk - 16, seedA, 16);
	scloudplus_packsk(S, sk);
	free(S);
	free(E);
	free(B);
}

void scloudplus_pkeenc(uint8_t *pk, uint8_t *m, uint8_t *r, uint8_t *ctx)
{
	uint16_t *S1 =
		(uint16_t *)malloc(sizeof(uint16_t) * scloudplus_mbar * scloudplus_m);
	uint16_t *E1 =
		(uint16_t *)malloc(sizeof(uint16_t) * scloudplus_mbar * scloudplus_n);
	uint16_t *E2 =
		(uint16_t *)malloc(sizeof(uint16_t) * scloudplus_mbar * scloudplus_nbar);
	uint16_t *mu0 =
		(uint16_t *)malloc(sizeof(uint16_t) * scloudplus_mbar * scloudplus_nbar);
	uint16_t *C1 =
		(uint16_t *)malloc(sizeof(uint16_t) * scloudplus_mbar * scloudplus_n);
	uint16_t *C2 =
		(uint16_t *)malloc(sizeof(uint16_t) * scloudplus_mbar * scloudplus_nbar);
	uint16_t *B =
		(uint16_t *)malloc(sizeof(uint16_t) * scloudplus_m * scloudplus_nbar);
	uint8_t seed[64];
	uint8_t *seedA = pk + scloudplus_pk - 16;
	uint8_t *r1 = seed;
	uint8_t *r2 = seed + 32;
	scloudplus_F(seed, 64, r, 32);
	scloudplus_samplephi(r1, S1);
	scloudplus_sampleeta2(r2, E1, E2);
	scloudplus_msgencode(m, mu0);
	scloudplus_unpackpk(pk, B);
	scloudplus_mul_add_sa_e(seedA, S1, E1, C1);
	scloudplus_mul_add_sb_e(S1, B, E2, C2);
	scloudplus_add(C2, mu0, scloudplus_mbar * scloudplus_nbar, C2);
	scloudplus_compressc1(C1, C1);
	scloudplus_compressc2(C2, C2);
	scloudplus_packc1(C1, ctx);
	scloudplus_packc2(C2, ctx + scloudplus_c1);
	free(S1);
	free(E1);
	free(E2);
	free(mu0);
	free(C1);
	free(C2);
	free(B);
}

void scloudplus_pkedec(uint8_t *sk, uint8_t *ctx, uint8_t *m)
{
	uint16_t *S =
		(uint16_t *)malloc(sizeof(uint16_t) * scloudplus_n * scloudplus_nbar);
	uint16_t *C1 =
		(uint16_t *)malloc(sizeof(uint16_t) * scloudplus_mbar * scloudplus_n);
	uint16_t *C2 =
		(uint16_t *)malloc(sizeof(uint16_t) * scloudplus_mbar * scloudplus_nbar);
	uint16_t *D =
		(uint16_t *)malloc(sizeof(uint16_t) * scloudplus_mbar * scloudplus_nbar);
	scloudplus_unpacksk(sk, S);
	scloudplus_unpackc1(ctx, C1);
	scloudplus_unpackc2(ctx + scloudplus_c1, C2);
	scloudplus_decompressc1(C1, C1);
	scloudplus_decompressc2(C2, C2);
	scloudplus_mul_cs(C1, S, D);
	scloudplus_sub(C2, D, scloudplus_mbar * scloudplus_nbar, D);
	scloudplus_msgdecode(D, m);
	free(S);
	free(C1);
	free(C2);
	free(D);
}

/* ========================================================================
	* Masked PKE implementation (first-order arithmetic masking)
	* ======================================================================== */

void scloudplus_pkekeygen_masked(uint8_t *pk, uint8_t *sk)
{
	size_t s_len = (size_t)scloudplus_n * scloudplus_nbar;
	size_t b_len = (size_t)scloudplus_m * scloudplus_nbar;

	uint16_t *share0 = (uint16_t *)malloc(sizeof(uint16_t) * s_len);
	uint16_t *share1 = (uint16_t *)malloc(sizeof(uint16_t) * s_len);
	uint16_t *E = (uint16_t *)malloc(sizeof(uint16_t) * b_len);
	uint16_t *B = (uint16_t *)malloc(sizeof(uint16_t) * b_len);

	uint8_t alpha[32], seed[80];
	uint8_t *seedA = seed;
	uint8_t *r1 = seed + 16;
	uint8_t *r2 = seed + 48;

	randombytes(alpha, 32);
	scloudplus_F(seed, 80, alpha, 32);

	/* Masked sampling: S = share0 + share1 (mod q) */
	scloudplus_masked_samplepsi(r1, share0, share1);
	scloudplus_sampleeta1(r2, E);

	/* Fused: B = A * share0 + A * share1 + E, with A expanded only once */
	scloudplus_mul_add_as_e_2shares(seedA, share0, share1, E, B);

	/* Pack public key */
	scloudplus_packpk(B, pk);
	memcpy(pk + scloudplus_pk - 16, seedA, 16);

	/* We need to recover the unmasked S to pack sk,
	 * since sk format stores packed ternary S.
	 * Reconstruct: S = (share0 + share1) mod q */
	uint16_t *S = (uint16_t *)malloc(sizeof(uint16_t) * s_len);
	for (size_t i = 0; i < s_len; i++)
	{
		S[i] = (share0[i] + share1[i]) & 0xFFF;
	}
	scloudplus_packsk(S, sk);

	/* Securely erase sensitive data */
	memset(share0, 0, sizeof(uint16_t) * s_len);
	memset(share1, 0, sizeof(uint16_t) * s_len);
	memset(S, 0, sizeof(uint16_t) * s_len);

	free(share0);
	free(share1);
	free(E);
	free(B);
	free(S);
}

void scloudplus_pkeenc_masked(uint8_t *pk, uint8_t *m, uint8_t *r,
							  uint8_t *ctx)
{
	size_t sp_len = (size_t)scloudplus_mbar * scloudplus_m;
	size_t c1_len = (size_t)scloudplus_mbar * scloudplus_n;
	size_t c2_len = (size_t)scloudplus_mbar * scloudplus_nbar;

	uint16_t *share0 = (uint16_t *)malloc(sizeof(uint16_t) * sp_len);
	uint16_t *share1 = (uint16_t *)malloc(sizeof(uint16_t) * sp_len);
	uint16_t *E1 = (uint16_t *)malloc(sizeof(uint16_t) * c1_len);
	uint16_t *E2 = (uint16_t *)malloc(sizeof(uint16_t) * c2_len);
	uint16_t *mu0 = (uint16_t *)malloc(sizeof(uint16_t) * c2_len);
	uint16_t *C1 = (uint16_t *)malloc(sizeof(uint16_t) * c1_len);
	uint16_t *C2 = (uint16_t *)malloc(sizeof(uint16_t) * c2_len);
	uint16_t *B = (uint16_t *)malloc(sizeof(uint16_t) * scloudplus_m *
									  scloudplus_nbar);

	uint8_t seed[64];
	uint8_t *seedA = pk + scloudplus_pk - 16;
	uint8_t *r1 = seed;
	uint8_t *r2 = seed + 32;

	scloudplus_F(seed, 64, r, 32);

	/* Masked sampling: S' = share0 + share1 (mod q) */
	scloudplus_masked_samplephi(r1, share0, share1);
	scloudplus_sampleeta2(r2, E1, E2);

	scloudplus_msgencode(m, mu0);
	scloudplus_unpackpk(pk, B);

	/* Fused: C1 = share0 * A + share1 * A + E1, with A expanded only once */
	scloudplus_mul_add_sa_e_2shares(seedA, share0, share1, E1, C1);

	/* C2 = share0 * B + E2 */
	scloudplus_mul_add_sb_e(share0, B, E2, C2);
	/* C2 += share1 * B (accumulate second share) */
	scloudplus_mul_add_sb(share1, B, C2);

	/* C2 += mu (message encoding) */
	scloudplus_add(C2, mu0, scloudplus_mbar * scloudplus_nbar, C2);

	scloudplus_compressc1(C1, C1);
	scloudplus_compressc2(C2, C2);
	scloudplus_packc1(C1, ctx);
	scloudplus_packc2(C2, ctx + scloudplus_c1);

	/* Securely erase shares */
	memset(share0, 0, sizeof(uint16_t) * sp_len);
	memset(share1, 0, sizeof(uint16_t) * sp_len);

	free(share0);
	free(share1);
	free(E1);
	free(E2);
	free(mu0);
	free(C1);
	free(C2);
	free(B);
}

void scloudplus_pkedec_masked(uint8_t *sk, uint8_t *ctx, uint8_t *m)
{
	size_t s_len = (size_t)scloudplus_n * scloudplus_nbar;
	size_t d_len = (size_t)scloudplus_mbar * scloudplus_nbar;

	uint16_t *S = (uint16_t *)malloc(sizeof(uint16_t) * s_len);
	uint16_t *share0 = (uint16_t *)malloc(sizeof(uint16_t) * s_len);
	uint16_t *share1 = (uint16_t *)malloc(sizeof(uint16_t) * s_len);
	uint16_t *C1 =
		(uint16_t *)malloc(sizeof(uint16_t) * scloudplus_mbar * scloudplus_n);
	uint16_t *C2 = (uint16_t *)malloc(sizeof(uint16_t) * d_len);
	uint16_t *D = (uint16_t *)malloc(sizeof(uint16_t) * d_len);

	/* Step 1: Recover plaintext S from packed sk */
	scloudplus_unpacksk(sk, S);

	/* Step 2: Generate fresh randomness beta and re-share S */
	uint8_t beta[32];
	randombytes(beta, 32);
	scloudplus_reshare_s(S, beta, share0, share1);

	/* Securely erase plaintext S immediately */
	memset(S, 0, sizeof(uint16_t) * s_len);

	/* Step 3: Unpack and decompress ciphertext */
	scloudplus_unpackc1(ctx, C1);
	scloudplus_unpackc2(ctx + scloudplus_c1, C2);
	scloudplus_decompressc1(C1, C1);
	scloudplus_decompressc2(C2, C2);

	/* Step 4: Masked matrix multiplication
	 * D = C1 * share0 + C1 * share1 = C1 * S (mod q)
	 * Done in two separate passes to prevent leakage */
	memset(D, 0, sizeof(uint16_t) * d_len);
	scloudplus_mul_add_cs(C1, share0, D);
	scloudplus_mul_add_cs(C1, share1, D);

	/* Step 5: D = C2 - D */
	scloudplus_sub(C2, D, scloudplus_mbar * scloudplus_nbar, D);

	/* Step 6: Decode message */
	scloudplus_msgdecode(D, m);

	/* Securely erase all sensitive data */
	memset(share0, 0, sizeof(uint16_t) * s_len);
	memset(share1, 0, sizeof(uint16_t) * s_len);
	memset(beta, 0, 32);

	free(S);
	free(share0);
	free(share1);
	free(C1);
	free(C2);
	free(D);
}
