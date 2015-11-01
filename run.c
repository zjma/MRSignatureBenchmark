#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "benchmark.h"


int main(int argc, char **argv)
{
    int i;

    int sec = 1024;
    int rec = 512;
    int red = 512;

    int sch_id = SCHID_ECOMG;
    int bitlen_sec = 256;
    int bitlen_rec = 256;
    int bitlen_red = 128;
    int bitlen_clr = 256;
    int sigcount = 1000;

    InitCrypt();

    for (i=1; i<argc; i++)
    {
        if (strcmp(argv[i], "-sec") == 0)
        {
            assert(i<argc-1);
            i++;
            sec = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-rec") == 0)
        {
            assert(i<argc-1);
            i++;
            rec = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-red") == 0)
        {
            assert(i<argc-1);
            i++;
            red = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-sigcount") == 0)
        {
            assert(i<argc-1);
            i++;
            sigcount = atoi(argv[i]);
        }
        else
        {
            if (strcmp(argv[i], "ao") == 0)
                sch_id = SCHID_AO;
            else if (strcmp(argv[i], "pv") == 0)
                sch_id = SCHID_PV;
            else if (strcmp(argv[i], "omg") == 0)
                sch_id = SCHID_OMG;
            else if (strcmp(argv[i], "ecao") == 0)
                sch_id = SCHID_ECAO;
            else if (strcmp(argv[i], "ecpv") == 0)
                sch_id = SCHID_ECPV;
            else if (strcmp(argv[i], "ecomg") == 0)
                sch_id = SCHID_ECOMG;
            else
                assert(0);
        }
    }
    clock_t s_tot = 0;
    clock_t son_tot = 0;
    clock_t v_tot = 0;
    clock_t von_tot = 0;
    test(sch_id, bitlen_sec,
            bitlen_rec, bitlen_red, bitlen_clr, sigcount,
            &s_tot, &son_tot, &v_tot, &von_tot);
}
