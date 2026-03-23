#ifndef _SCLOUDPLUS_PKE_H_
#define _SCLOUDPLUS_PKE_H_
#include <stdint.h>
void scloudplus_pkekeygen(uint8_t *pk, uint8_t *sk);
void scloudplus_pkeenc(uint8_t *pk, uint8_t *m, uint8_t *r, uint8_t *ctx);
void scloudplus_pkedec(uint8_t *sk, uint8_t *ctx, uint8_t *m);

/* ---- Masked PKE (first-order arithmetic masking) ---- */

/**
 * Masked PKE.KeyGen: generates (pk, sk) with masked secret S.
 * pk = (seedA, B = A * S + E), sk = packsk(S).
 * S is internally split into (share_0, share_1) to compute B = A*share_0 + E + A*share_1,
 * so the unmasked S never touches a multiplication bus register.
 * The output format is identical to the standard KeyGen.
 */
void scloudplus_pkekeygen_masked(uint8_t *pk, uint8_t *sk);

/**
 * Masked PKE.Enc: encrypts message m under pk using randomness r.
 * S' is internally split into shares for side-channel protection.
 * Output ciphertext format is identical to the standard Enc.
 */
void scloudplus_pkeenc_masked(uint8_t *pk, uint8_t *m, uint8_t *r,
							  uint8_t *ctx);

/**
 * Masked PKE.Dec: decrypts ciphertext ctx using sk.
 * Internally recovers S from sk, generates fresh random beta,
 * re-shares S into (share'_0, share'_1), then computes
 * D = C'_1 * share'_0 + C'_1 * share'_1 in two separate passes.
 */
void scloudplus_pkedec_masked(uint8_t *sk, uint8_t *ctx, uint8_t *m);

#endif