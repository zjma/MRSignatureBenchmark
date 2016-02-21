#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "benchmark.h"

void print_usage(){
    printf(
"\nUSAGE:\n"
"   run     [-v] [-phase p] scheme [-sec n] [-clr lp -rec lr -red ld]\n"
"           [-sigcount x] [-usrcount y]\n"
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
"   scheme      specifies the scheme to be tested.\n"
"               scheme should be one of the following:\n"
"               ecao, ecpv-x, ecpv-a, eco-p, eco-x, eco-a. \n\n"
"   -sec n      security parameter.\n"
"               n should be 160, 192, 224, 256, 384, or 521.(Default: 256).\n"
"\n"
"   -clr lp     length of plaintext part in bit.(Default: 0)\n\n"
"   -rec lr     length of recoverable part in bit.(Default: n/2).\n\n"
"   -red ld     length of additional redundancy.(Default: n-n/2)\n\n"
"   -usrcount y number of key-pairs to test.(Default: 10)\n\n"
"   -sigcount x number of signatures to gen/verify per keypair.(Default: 100)\n\n"
//"   -v          verbose mode.\n\n"
//"   -vv         more information.\n\n"
"   -phase p    specifies where we stop in each process.\n"
"               p should be:\n"
"                   1(one repeat will be: sign-offline),\n"
"                   2(one repeat will be: sign-offline,sign-online), or\n"
"                   4(one repeat will both sign and verify).\n"
"               Default value of p is 4.\n\n");
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
    int bitlen_rec = -1;
    int bitlen_red = -1;
    int bitlen_clr = -1;
    int sigcount = 100;
    int usrcount = 10;
    int verbose=1;
    int phase=4;
    int simple=0;
    InitCrypt();

    for (i=1; i<argc; i++)
    {
        if (strcmp(argv[i], "-v")==0)
        {
            verbose=1;
        }
        else if (strcmp(argv[i], "-s")==0)
        {
            simple=1;
        }
        else if (strcmp(argv[i],"-vv")==0)
        {
            verbose=2;
        }
        else if (strcmp(argv[i],"-phase")==0)
        {
            show_usage_and_exit_if(i==argc-1);
            i++;
            phase=atoi(argv[i]);
            if (phase!=1&&phase!=2&&phase!=4) show_usage_and_exit_if(1);
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
        else if (strcmp(argv[i], "-sigcount") == 0)
        {
            show_usage_and_exit_if(i==argc-1);
            i++;
            sigcount = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-usrcount") == 0)
        {
            show_usage_and_exit_if(i==argc-1);
            i++;
            usrcount = atoi(argv[i]);
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

    if (bitlen_rec==-1&&bitlen_red==-1&&bitlen_clr==-1){
        bitlen_clr=0;
        bitlen_rec=bitlen_sec/2;
        bitlen_red=bitlen_sec-bitlen_rec;
    }

    if (bitlen_rec==-1||bitlen_red==-1||bitlen_clr==-1)
        show_usage_and_exit_if(1);

    bitlen_clr-=bitlen_clr%8;
    bitlen_rec-=bitlen_rec%8;
    bitlen_red-=bitlen_red%8;

    clock_t s_tot = 0;
    clock_t son_tot = 0;
    clock_t v_tot = 0;
    clock_t von_tot = 0;
    test(verbose, phase,sch_id, bitlen_sec,
            bitlen_rec, bitlen_red, bitlen_clr,
            sigcount, usrcount,
            &s_tot, &son_tot, &v_tot, &von_tot);

    if (simple==1)
    {
        printf("%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,\n",
                getnamebyschid(sch_id),
                bitlen_sec,bitlen_clr,bitlen_rec,bitlen_red,usrcount,sigcount,
                (int)son_tot,(int)s_tot,(int)von_tot,(int)v_tot);
    }
    else if (verbose) printf( "\nResults for %d requests:\n"
            "Sign tot:        %d\n"
            "Sign online tot: %d\n"
            "Vrfy tot:        %d\n"
            "Vrfy online tot: %d\n",
            sigcount*usrcount,
            (int)s_tot,
            (int)son_tot,
            (int)v_tot,
            (int)von_tot);
    return 0;
}
