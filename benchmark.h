/**
 * \file benchmark.h
 */

#ifndef __BENCHMARK_H__
#define __BENCHMARK_H__


#include <time.h>

/* Scheme IDs in this project. */
#define SCHID_OMG   0x0000
#define SCHID_ECOMG 0x0e00
#define SCHID_AO    0x0001
#define SCHID_ECAO  0x0e01
#define SCHID_PV    0x0002
#define SCHID_ECPV  0x0e02


/* Security levels in this project. */
#define SEC_256   256
#define SEC_512   512


/**
 * Select a scheme, specify params, and run the scheme.
 *
 * \param schid         Which scheme? Use SCHID_* here.
 * \param bitlen_sec    Security parameter. Use SEC_* here.
 * \param bitlen_rec    Length of recoverable part (in bit).
 * \param bitlen_red    Length of additional redundancy (in bit).
 * \param bitlen_clr    Length of plain part (in bit).
 * \param sign_count    How many signature to generate.
 *
 * \param ret_sign_tot  Total signing time will go here.
 * \param ret_sign_onl  Online signing time will go here.
 * \param ret_vrfy_tot  Total vrfying time will go here.
 * \param ret_vrfy_onl  Online vrfying time will go here.
 *
 * \return  0(OK), or -1(failed).
 */
int test(int schid, int bitlen_sec,
    int bitlen_rec, int bitlen_red, int bitlen_clr, int sign_count,
    clock_t *ret_sign_tot, clock_t *ret_sign_onl,
    clock_t *ret_vrfy_tot, clock_t *ret_vrfy_onl);


#endif
