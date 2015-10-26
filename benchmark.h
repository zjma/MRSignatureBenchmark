#ifndef __BENCHMARK_H__
#define __BENCHMARK_H__

#include "scheme.h"

#define SCHID_OMG   0x0000
#define SCHID_ECOMG 0x0e00
#define SCHID_AO    0x0001
#define SCHID_ECAO  0x0e01
#define SCHID_PV    0x0002
#define SCHID_ECPV  0x0e02

int test(int schid, int bitlen_sec, int bitlen_rec, int bitlen_red, int bitlen_clr, int sign_count);

#endif
