#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "benchmark.h"

void print_usage(){
    printf(
"USAGE:\n"
"   run     [-v] scheme [-sec n] [-clr lp] [-rec lr] [-red ld] [-count x]\n"
"\n"
"DESCRIPTION\n"
"   This program times a message recovery signature scheme you specified,\n"
"   and prints the time used to generate signatures, the time\n"
"   spent on the online phases, and the time used to verify signatures.\n"
"\n"
"   Currently supported schemes are ECAO, ECPV-XOR, ECPV-AES,\n"
"   EC-Omega-Plain, EC-Omega-XOR and EC-Omega-AES.\n"
"\n"
"ARGUMENTS\n"
"\n"
"   scheme      specifies the scheme to be tested.\n"
"               scheme should be one of the following:\n"
"               ecao, ecpv-x, ecpv-a, eco-p, eco-x, eco-a. \n\n"
"   -sec n      specifies the security parameter.\n"
"               n should be one of the following: 160,224,256,384,512.\n"
"               Default value is 256.\n\n"
"   -clr lp     specifies the length of plaintext part in bit.\n"
"               lp should be any non-negative integer.\n"
"               Default value is 128\n\n"
"   -rec lr     specifies the length of recoverable part in bit.\n"
"               lr should ne any non-negative integer.\n"
"               Default value is 128.\n\n"
"   -red ld     specifies the length of additional redundancy.\n"
"               ld should be any non-negative integer.\n"
"               Default value is 128\n\n"
"   -count x    specifies how many times you want to repeat.\n"
"               x should ne any non-negative integer.\n"
"               Default valuye is 1000.\n\n"
"   -v          verbose mode.\n\n");
}


void show_usage_and_exit_if(int v){
    if (v==0) return;
    print_usage();
    exit(1);
}


int main(int argc, char **argv)
{
    int i;
    
    int sch_id = -1;
    int bitlen_sec = 256;
    int bitlen_rec = 256;
    int bitlen_red = 256;
    int bitlen_clr = 0;
    int sigcount = 1000;
    int verbose=0;
    InitCrypt();

    for (i=1; i<argc; i++)
    {
        if (strcmp(argv[i], "-v")==0)
        {
            verbose=1;
        }
        else if (strcmp(argv[i], "-sec") == 0)
        {
            show_usage_and_exit_if(i==argc-1);
            i++;
            bitlen_sec = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-rec") == 0)
        {
            show_usage_and_exit_if(i==argc-1);
            i++;
            bitlen_rec = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-clr") == 0)
        {
            show_usage_and_exit_if(i==argc-1);
            i++;
            bitlen_clr = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-red") == 0)
        {
            show_usage_and_exit_if(i==argc-1);
            i++;
            bitlen_red = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-count") == 0)
        {
            show_usage_and_exit_if(i==argc-1);
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
            else if (strcmp(argv[i], "ecpv-a") == 0)
                sch_id = SCHID_ECPV1;
            else if (strcmp(argv[i], "ecpv-x") == 0)
                sch_id = SCHID_ECPV0;
            else if (strcmp(argv[i], "eco-a") == 0)
                sch_id = SCHID_ECOMG2;
            else if (strcmp(argv[i], "eco-x") == 0)
                sch_id = SCHID_ECOMG1;
            else if (strcmp(argv[i], "eco-p") == 0)
                sch_id = SCHID_ECOMG0;
            else
                show_usage_and_exit_if(1);
        }
    }
    show_usage_and_exit_if(sch_id==-1);

    clock_t s_tot = 0;
    clock_t son_tot = 0;
    clock_t v_tot = 0;
    clock_t von_tot = 0;
    test(verbose,sch_id, bitlen_sec,
            bitlen_rec, bitlen_red, bitlen_clr, sigcount,
            &s_tot, &son_tot, &v_tot, &von_tot);

    printf( "\nResults for %d requests:\n"
            "Sign tot:        %d\n"
            "Sign online tot: %d\n"
            "Vrfy tot:        %d\n"
            "Vrfy online tot: %d\n",
            sigcount,
            (int)s_tot,
            (int)son_tot,
            (int)v_tot,
            (int)von_tot);

}
