#ifndef _SCLOUDPLUS_KEM_H_
#define _SCLOUDPLUS_KEM_H_
#include <stdint.h>
void scloud_kemkeygen(uint8_t *pk, uint8_t *sk);
void scloud_kemencaps(uint8_t *pk, uint8_t *ctx, uint8_t *ss);
void scloud_kemdecaps(uint8_t *sk, uint8_t *ctx, uint8_t *ss);

/* ---- Masked KEM (first-order arithmetic masking) ---- */

/**
 * Masked KEM.KeyGen: uses masked PKE.KeyGen internally.
 * Output format is identical to the standard KEM.KeyGen.
 */
void scloud_kemkeygen_masked(uint8_t *pk, uint8_t *sk);

/**
 * Masked KEM.Encaps: uses masked PKE.Enc internally.
 * Output format is identical to the standard KEM.Encaps.
 */
void scloud_kemencaps_masked(uint8_t *pk, uint8_t *ctx, uint8_t *ss);

/**
 * Masked KEM.Decaps: uses masked PKE.Dec internally.
 * Generates fresh randomness beta for re-sharing S during decryption.
 */
void scloud_kemdecaps_masked(uint8_t *sk, uint8_t *ctx, uint8_t *ss);

#endif