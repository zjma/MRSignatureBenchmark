/**
 * \file benchmark.h
 */

#ifndef __BENCHMARK_H__
#define __BENCHMARK_H__


#include <time.h>

/* Scheme IDs in this project. */
#define SCHID_OMG       0x000000
#define SCHID_ECOMG0    0x0e0000  // No covering
#define SCHID_ECOMG1    0x0e0001  // XOR covering
#define SCHID_ECOMG2    0x0e0002  // AES covering
#define SCHID_AO        0x000100
#define SCHID_ECAO      0x0e0100
#define SCHID_PV        0x000200
#define SCHID_ECPV0     0x0e0200  // XOR covering
#define SCHID_ECPV1     0x0e0201  // AES covering


/* Security levels in this project. */
#define SEC_256   256
#define SEC_512   512


/**
 * Select a scheme, specify params, and run the scheme.
 *
 * \param verbose       Whether to enable verbose mode.
 * \param breakpoint    Where to stop in one run?
 * \param schid         Which scheme? Use SCHID_* here.
 * \param bitlen_sec    Security parameter. Use SEC_* here.
 * \param bitlen_rec    Length of recoverable part (in bit).
 * \param bitlen_red    Length of additional redundancy (in bit).
 * \param bitlen_clr    Length of plain part (in bit).
 * \param sign_count    How many signatures to generate for one signer.
 * \param user_count    How many signers.
 *
 * \param ret_sign_tot  Total signing time will go here.
 * \param ret_sign_onl  Online signing time will go here.
 * \param ret_vrfy_tot  Total vrfying time will go here.
 * \param ret_vrfy_onl  Online vrfying time will go here.
 *
 * \return  0(OK), or -1(failed).
 */
int test(int verbose, int breakpoint, int schid, int bitlen_sec,
    int bitlen_rec, int bitlen_red, int bitlen_clr,
    int sign_count, int user_count,
    clock_t *ret_sign_tot, clock_t *ret_sign_onl,
    clock_t *ret_vrfy_tot, clock_t *ret_vrfy_onl);


const char* getnamebyschid(int schid);

#endif
