#ifndef _SCLOUDPLUS_SAMPLE_H_
#define _SCLOUDPLUS_SAMPLE_H_
#include "aes.h"
#include "param.h"
void scloudplus_mul_add_as_e(const uint8_t *seedA, const uint16_t *S,
							 const uint16_t *E, uint16_t *B);
void scloudplus_mul_add_sa_e(const uint8_t *seedA, const uint16_t *S,
							 uint16_t *E, uint16_t *C);
void scloudplus_sampleeta1(uint8_t *seed, uint16_t *matrixE);
void scloudplus_sampleeta2(uint8_t *seed, uint16_t *matrixe1,
						   uint16_t *matrixe2);
void scloudplus_samplepsi(uint8_t *seed, uint16_t *matrixs);
void scloudplus_samplephi(uint8_t *seed, uint16_t *matrixs);

/* ---- Masked sampling (first-order arithmetic masking) ---- */

/**
 * Masked Psi sampling for secret matrix S (n x nbar).
 * Generates two shares (share0, share1) in Z_q such that
 * (share0 + share1) mod q = S, where S is the ternary matrix
 * sampled from seed using the original Psi distribution.
 */
void scloudplus_masked_samplepsi(uint8_t *seed, uint16_t *share0,
								 uint16_t *share1);

/**
 * Masked Phi sampling for secret matrix S' (mbar x m).
 * Generates two shares (share0, share1) in Z_q such that
 * (share0 + share1) mod q = S'.
 */
void scloudplus_masked_samplephi(uint8_t *seed, uint16_t *share0,
								 uint16_t *share1);

/**
 * Re-share an existing ternary secret S (n x nbar) into fresh shares.
 * Uses random seed beta to generate share0, then computes
 * share1 = (S - share0) mod q.
 */
void scloudplus_reshare_s(const uint16_t *S, const uint8_t *beta,
						  uint16_t *share0, uint16_t *share1);

/**
 * Accumulate A * S onto B (without adding E).
 * Computes B += A * S, where A is generated from seedA.
 */
void scloudplus_mul_add_as(const uint8_t *seedA, const uint16_t *S,
						   uint16_t *B);

/**
 * Accumulate S * A onto C (without adding E).
 * Computes C += S * A, where A is generated from seedA.
 */
void scloudplus_mul_add_sa(const uint8_t *seedA, const uint16_t *S,
						   uint16_t *C);

#endif