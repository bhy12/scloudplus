#include "ds_benchmark.h"
#include "encode.h"
#include "kem.h"
#include "random.h"
#include "param.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define KEM_TEST_ITERATIONS 100
#define KEM_BENCH_SECONDS 1
#define KEM_MEDIAN_ITERATIONS 1000
#if (scloudplus_l == 128)
#define SYSTEM_NAME "scloud plus 128"
#elif (scloudplus_l == 192)
#define SYSTEM_NAME "scloud plus 192"
#elif (scloudplus_l == 256)
#define SYSTEM_NAME "scloud plus 256"
#endif
static int kem_test(const char *named_parameters, int iterations)
{
	uint8_t pk[scloudplus_pk];
	uint8_t sk[scloudplus_kem_sk];
	uint8_t ctx[scloudplus_ctx];
	uint8_t ssa[scloudplus_ss];
	uint8_t ssb[scloudplus_ss];
	scloud_kemkeygen(pk, sk);
	scloud_kemencaps(pk, ctx, ssa);
	scloud_kemdecaps(sk, ctx, ssb);

	printf("====================================================================="
		   "========================================================\n");
	printf("Testing correctness of key encapsulation mechanism (KEM),system %s,"
		   "tests for %d iterations\n",
		   named_parameters, iterations);
	printf("====================================================================="
		   "========================================================\n");

	for (int i = 0; i < KEM_TEST_ITERATIONS; i++)
	{

		scloud_kemkeygen(pk, sk);
		scloud_kemencaps(pk, ctx, ssa);
		scloud_kemdecaps(sk, ctx, ssb);
		if (memcmp(ssa, ssb, scloudplus_ss) != 0)
		{
			printf("\n");
			for (int i = 0; i < scloudplus_ss; i++)
			{
				printf("%d ", ssa[i]);
			}
			printf("\n");
			for (int i = 0; i < scloudplus_ss; i++)
			{
				printf("%d ", ssb[i]);
			}
			printf("wrong id is %d", i);
			printf("\n");
			return false;
		}
	}
	printf("Tests PASSED. All session keys matched.\n");

	return true;
}

/* ---- Masked KEM correctness test ---- */
static int kem_test_masked(const char *named_parameters, int iterations)
{
	uint8_t pk[scloudplus_pk];
	uint8_t sk[scloudplus_kem_sk];
	uint8_t ctx[scloudplus_ctx];
	uint8_t ssa[scloudplus_ss];
	uint8_t ssb[scloudplus_ss];

	printf("====================================================================="
		   "========================================================\n");
	printf("Testing correctness of MASKED KEM, system %s, "
		   "tests for %d iterations\n",
		   named_parameters, iterations);
	printf("====================================================================="
		   "========================================================\n");

	for (int i = 0; i < iterations; i++)
	{
		scloud_kemkeygen_masked(pk, sk);
		scloud_kemencaps_masked(pk, ctx, ssa);
		scloud_kemdecaps_masked(sk, ctx, ssb);
		if (memcmp(ssa, ssb, scloudplus_ss) != 0)
		{
			printf("MASKED KEM FAILED at iteration %d\n", i);
			printf("ssa: ");
			for (int j = 0; j < scloudplus_ss; j++)
				printf("%02x", ssa[j]);
			printf("\nssb: ");
			for (int j = 0; j < scloudplus_ss; j++)
				printf("%02x", ssb[j]);
			printf("\n");
			return false;
		}
	}
	printf("Masked KEM Tests PASSED. All session keys matched.\n");
	return true;
}

/* ---- Cross-compatibility test: masked keygen/enc <-> standard dec, and vice versa ---- */
static int kem_test_cross(const char *named_parameters, int iterations)
{
	uint8_t pk[scloudplus_pk];
	uint8_t sk[scloudplus_kem_sk];
	uint8_t ctx[scloudplus_ctx];
	uint8_t ssa[scloudplus_ss];
	uint8_t ssb[scloudplus_ss];

	printf("====================================================================="
		   "========================================================\n");
	printf("Testing cross-compatibility (masked <-> standard), system %s, "
		   "tests for %d iterations\n",
		   named_parameters, iterations);
	printf("====================================================================="
		   "========================================================\n");

	/* Test 1: Standard keygen, masked encaps, masked decaps */
	for (int i = 0; i < iterations; i++)
	{
		scloud_kemkeygen(pk, sk);
		scloud_kemencaps_masked(pk, ctx, ssa);
		scloud_kemdecaps_masked(sk, ctx, ssb);
		if (memcmp(ssa, ssb, scloudplus_ss) != 0)
		{
			printf("Cross test 1 FAILED at iteration %d\n", i);
			return false;
		}
	}
	printf("  Cross test 1 PASSED (std keygen + masked enc/dec).\n");

	/* Test 2: Masked keygen, standard encaps, masked decaps */
	for (int i = 0; i < iterations; i++)
	{
		scloud_kemkeygen_masked(pk, sk);
		scloud_kemencaps(pk, ctx, ssa);
		scloud_kemdecaps_masked(sk, ctx, ssb);
		if (memcmp(ssa, ssb, scloudplus_ss) != 0)
		{
			printf("Cross test 2 FAILED at iteration %d\n", i);
			return false;
		}
	}
	printf("  Cross test 2 PASSED (masked keygen + std enc + masked dec).\n");

	/* Test 3: Masked keygen, masked encaps, standard decaps */
	for (int i = 0; i < iterations; i++)
	{
		scloud_kemkeygen_masked(pk, sk);
		scloud_kemencaps_masked(pk, ctx, ssa);
		scloud_kemdecaps(sk, ctx, ssb);
		if (memcmp(ssa, ssb, scloudplus_ss) != 0)
		{
			printf("Cross test 3 FAILED at iteration %d\n", i);
			return false;
		}
	}
	printf("  Cross test 3 PASSED (masked keygen/enc + std dec).\n");

	printf("All cross-compatibility tests PASSED.\n");
	return true;
}

/* ========================================================================
 * Median-based benchmark (matches original paper: Table 5)
 * "median count over 1000 measurements"
 * ======================================================================== */

static int cmp_uint64(const void *a, const void *b)
{
	uint64_t va = *(const uint64_t *)a;
	uint64_t vb = *(const uint64_t *)b;
	if (va < vb) return -1;
	if (va > vb) return 1;
	return 0;
}

static uint64_t median_u64(uint64_t *arr, int n)
{
	qsort(arr, n, sizeof(uint64_t), cmp_uint64);
	if (n % 2 == 1)
		return arr[n / 2];
	else
		return (arr[n / 2 - 1] + arr[n / 2]) / 2;
}

static void kem_bench_median(const int iterations)
{
	uint8_t pk[scloudplus_pk];
	uint8_t sk[scloudplus_kem_sk];
	uint8_t ctx[scloudplus_ctx];
	uint8_t ssa[scloudplus_ss];
	uint8_t ssb[scloudplus_ss];

	uint64_t *cycles_keygen  = (uint64_t *)malloc(sizeof(uint64_t) * iterations);
	uint64_t *cycles_encaps  = (uint64_t *)malloc(sizeof(uint64_t) * iterations);
	uint64_t *cycles_decaps  = (uint64_t *)malloc(sizeof(uint64_t) * iterations);
	uint64_t *cycles_encdec  = (uint64_t *)malloc(sizeof(uint64_t) * iterations);

	volatile uint64_t t0, t1;

	/* Warm up */
	scloud_kemkeygen(pk, sk);
	scloud_kemencaps(pk, ctx, ssa);
	scloud_kemdecaps(sk, ctx, ssb);

	for (int i = 0; i < iterations; i++)
	{
		t0 = rdtsc();
		scloud_kemkeygen(pk, sk);
		t1 = rdtsc();
		cycles_keygen[i] = (t1 >= t0) ? (t1 - t0) : (t1 + ((uint64_t)1 << 32) - t0);

		t0 = rdtsc();
		scloud_kemencaps(pk, ctx, ssa);
		t1 = rdtsc();
		cycles_encaps[i] = (t1 >= t0) ? (t1 - t0) : (t1 + ((uint64_t)1 << 32) - t0);

		t0 = rdtsc();
		scloud_kemdecaps(sk, ctx, ssb);
		t1 = rdtsc();
		cycles_decaps[i] = (t1 >= t0) ? (t1 - t0) : (t1 + ((uint64_t)1 << 32) - t0);

		cycles_encdec[i] = cycles_encaps[i] + cycles_decaps[i];
	}

	uint64_t med_kg = median_u64(cycles_keygen, iterations);
	uint64_t med_en = median_u64(cycles_encaps, iterations);
	uint64_t med_de = median_u64(cycles_decaps, iterations);
	uint64_t med_ed = median_u64(cycles_encdec, iterations);

	printf("%-30s %12" PRIu64 "\n", "KeyGen",            med_kg);
	printf("%-30s %12" PRIu64 "\n", "Encaps",            med_en);
	printf("%-30s %12" PRIu64 "\n", "Decaps",            med_de);
	printf("%-30s %12" PRIu64 "\n", "Encaps + Decaps",   med_ed);

	free(cycles_keygen);
	free(cycles_encaps);
	free(cycles_decaps);
	free(cycles_encdec);
}

static void kem_bench_median_masked(const int iterations)
{
	uint8_t pk[scloudplus_pk];
	uint8_t sk[scloudplus_kem_sk];
	uint8_t ctx[scloudplus_ctx];
	uint8_t ssa[scloudplus_ss];
	uint8_t ssb[scloudplus_ss];

	uint64_t *cycles_keygen  = (uint64_t *)malloc(sizeof(uint64_t) * iterations);
	uint64_t *cycles_encaps  = (uint64_t *)malloc(sizeof(uint64_t) * iterations);
	uint64_t *cycles_decaps  = (uint64_t *)malloc(sizeof(uint64_t) * iterations);
	uint64_t *cycles_encdec  = (uint64_t *)malloc(sizeof(uint64_t) * iterations);

	volatile uint64_t t0, t1;

	/* Warm up */
	scloud_kemkeygen_masked(pk, sk);
	scloud_kemencaps_masked(pk, ctx, ssa);
	scloud_kemdecaps_masked(sk, ctx, ssb);

	for (int i = 0; i < iterations; i++)
	{
		t0 = rdtsc();
		scloud_kemkeygen_masked(pk, sk);
		t1 = rdtsc();
		cycles_keygen[i] = (t1 >= t0) ? (t1 - t0) : (t1 + ((uint64_t)1 << 32) - t0);

		t0 = rdtsc();
		scloud_kemencaps_masked(pk, ctx, ssa);
		t1 = rdtsc();
		cycles_encaps[i] = (t1 >= t0) ? (t1 - t0) : (t1 + ((uint64_t)1 << 32) - t0);

		t0 = rdtsc();
		scloud_kemdecaps_masked(sk, ctx, ssb);
		t1 = rdtsc();
		cycles_decaps[i] = (t1 >= t0) ? (t1 - t0) : (t1 + ((uint64_t)1 << 32) - t0);

		cycles_encdec[i] = cycles_encaps[i] + cycles_decaps[i];
	}

	uint64_t med_kg = median_u64(cycles_keygen, iterations);
	uint64_t med_en = median_u64(cycles_encaps, iterations);
	uint64_t med_de = median_u64(cycles_decaps, iterations);
	uint64_t med_ed = median_u64(cycles_encdec, iterations);

	printf("%-30s %12" PRIu64 "\n", "Masked KeyGen",            med_kg);
	printf("%-30s %12" PRIu64 "\n", "Masked Encaps",            med_en);
	printf("%-30s %12" PRIu64 "\n", "Masked Decaps",            med_de);
	printf("%-30s %12" PRIu64 "\n", "Masked Encaps + Decaps",   med_ed);

	free(cycles_keygen);
	free(cycles_encaps);
	free(cycles_decaps);
	free(cycles_encdec);
}

/* ---- Original mean-based benchmarks (kept for reference) ---- */

static void kem_bench(const int seconds)
{
	uint8_t pk[scloudplus_pk];
	uint8_t sk[scloudplus_kem_sk];
	uint8_t ctx[scloudplus_ctx];
	uint8_t ssa[scloudplus_ss];
	uint8_t ssb[scloudplus_ss];

	TIME_OPERATION_SECONDS({ scloud_kemkeygen(pk, sk); }, "Key generation", seconds);

	scloud_kemkeygen(pk, sk);
	TIME_OPERATION_SECONDS({ scloud_kemencaps(pk, ctx, ssa); }, "KEM encapsulate", seconds);

	scloud_kemencaps(pk, ctx, ssa);
	TIME_OPERATION_SECONDS({ scloud_kemdecaps(sk, ctx, ssb); }, "KEM decapsulate", seconds);

	TIME_OPERATION_SECONDS(
		{
			scloud_kemencaps(pk, ctx, ssa);
			scloud_kemdecaps(sk, ctx, ssb);
		},
		"KEM enc and decapsulate", seconds);
}

static void kem_bench_masked(const int seconds)
{
	uint8_t pk[scloudplus_pk];
	uint8_t sk[scloudplus_kem_sk];
	uint8_t ctx[scloudplus_ctx];
	uint8_t ssa[scloudplus_ss];
	uint8_t ssb[scloudplus_ss];

	TIME_OPERATION_SECONDS({ scloud_kemkeygen_masked(pk, sk); },
						   "Masked Key generation", seconds);

	scloud_kemkeygen_masked(pk, sk);
	TIME_OPERATION_SECONDS({ scloud_kemencaps_masked(pk, ctx, ssa); },
						   "Masked KEM encapsulate", seconds);

	scloud_kemencaps_masked(pk, ctx, ssa);
	TIME_OPERATION_SECONDS({ scloud_kemdecaps_masked(sk, ctx, ssb); },
						   "Masked KEM decapsulate", seconds);

	TIME_OPERATION_SECONDS(
		{
			scloud_kemencaps_masked(pk, ctx, ssa);
			scloud_kemdecaps_masked(sk, ctx, ssb);
		},
		"Masked KEM enc and decapsulate", seconds);
}

int main()
{
	int OK = true;

	/* Standard KEM test */
	OK = kem_test(SYSTEM_NAME, KEM_TEST_ITERATIONS);
	if (OK != true)
	{
		goto exit;
	}

	/* Masked KEM test */
	OK = kem_test_masked(SYSTEM_NAME, KEM_TEST_ITERATIONS);
	if (OK != true)
	{
		goto exit;
	}

	/* Cross-compatibility test */
	OK = kem_test_cross(SYSTEM_NAME, KEM_TEST_ITERATIONS);
	if (OK != true)
	{
		goto exit;
	}

	/* ============================================================
	 * Median-based benchmark (matching original paper methodology)
	 * "median count over 1000 measurements"
	 * ============================================================ */
	printf("\n");
	printf("====================================================================="
		   "========================================================\n");
	printf("Benchmark: median over %d measurements, %s\n",
		   KEM_MEDIAN_ITERATIONS, SYSTEM_NAME);
	printf("%-30s %12s\n", "Operation", "Cycles(median)");
	printf("====================================================================="
		   "========================================================\n");

	printf("\n--- Standard KEM (median) ---\n");
	kem_bench_median(KEM_MEDIAN_ITERATIONS);

	printf("\n--- Masked KEM (median) ---\n");
	kem_bench_median_masked(KEM_MEDIAN_ITERATIONS);

	/* ============================================================
	 * Mean-based benchmark (original ds_benchmark style)
	 * ============================================================ */
	printf("\n");
	printf("====================================================================="
		   "========================================================\n");
	printf("Benchmark: mean-based (run for %d seconds each), %s\n",
		   KEM_BENCH_SECONDS, SYSTEM_NAME);
	printf("====================================================================="
		   "========================================================\n");
	PRINT_TIMER_HEADER
	printf("\n--- Standard KEM (mean) ---\n");
	kem_bench(KEM_BENCH_SECONDS);
	printf("\n--- Masked KEM (mean) ---\n");
	kem_bench_masked(KEM_BENCH_SECONDS);

exit:
	return (OK == true) ? EXIT_SUCCESS : EXIT_FAILURE;
}
