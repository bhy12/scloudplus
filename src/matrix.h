#ifndef _SCLOUDPLUS_MATRIX_H_
#define _SCLOUDPLUS_MATRIX_H_
#include <stdint.h>

void scloudplus_add(uint16_t *in0, uint16_t *in1, int len, uint16_t *out);

void scloudplus_sub(uint16_t *in0, uint16_t *in1, int len, uint16_t *out);

void scloudplus_mul_cs(uint16_t *C, uint16_t *S, uint16_t *out);

void scloudplus_mul_add_sb_e(const uint16_t *S, const uint16_t *B,
							 const uint16_t *E, uint16_t *out);

/* ---- Masked matrix operations ---- */

/**
 * Accumulate C * S onto out: out += C * S (no memset).
 * Used in masked decryption: compute D += C'_1 * share_i for each share.
 */
void scloudplus_mul_add_cs(const uint16_t *C, const uint16_t *S,
						   uint16_t *out);

/**
 * Accumulate S * B onto out: out += S * B (no memset, no E).
 * Used in masked encryption: compute C_2 += share_i * B for each share.
 */
void scloudplus_mul_add_sb(const uint16_t *S, const uint16_t *B,
						   uint16_t *out);

#endif
