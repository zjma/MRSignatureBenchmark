/**
 * \file benchmark.c
 */
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <time.h>
//#include <sys/times.h>
#include "scheme.h"
#include "benchmark.h"

static struct timeval tm1;
static struct timeval tm2;
void timerstart(){gettimeofday(&tm1, NULL);}
void timerstop(){gettimeofday(&tm2, NULL);}
int getms(){
    unsigned long long t = 1000 * (tm2.tv_sec - tm1.tv_sec) + (tm2.tv_usec - tm1.tv_usec) / 1000;
    return t;
}
unsigned long long getus(){
    unsigned long long t = 1000000 * (tm2.tv_sec - tm1.tv_sec) + (tm2.tv_usec - tm1.tv_usec);
    return t;
}
int test_one_user(int breakpoint, int sign_count, Scheme* sch,
//        KeyPair *keypair, SignSession *signsess, VrfySession *vrfysess, Signature *sig,
        int bitlen_sec,
        int bitlen_clr, int bitlen_rec, int bitlen_red,
        clock_t *s_tot, clock_t *son_tot,
        clock_t *v_tot, clock_t *von_tot)
{
    int ret;
    clock_t c0,c1,c2,c3,c4,c5,c6,c7;
    uint32_t soff=0,son=0,voff=0,von=0;

    KeyPair *keypair = KeyPair_new(sch, bitlen_sec);
    assert(keypair != NULL);

    ret = KeyPair_gen(keypair);
    assert(ret == 0);

    int warming=1;
    for (++sign_count;sign_count>0;sign_count--){
        SignSession *signsess = SignSession_new(keypair, sch,
                bitlen_clr, bitlen_rec, bitlen_red);
        assert(signsess != NULL);

        VrfySession *vrfysess = VrfySession_new(keypair, sch,
                bitlen_clr, bitlen_rec, bitlen_red);
        assert(vrfysess != NULL);

        Signature *sig = Signature_new(keypair, sch, bitlen_clr, bitlen_rec, bitlen_red);
        assert(sig != NULL);

        int msglen = bitlen_rec/8 + bitlen_clr/8;
        unsigned char *msg = malloc(msglen);
        assert(msg != NULL);

        c0 = clock();
//        timerstart();
        ret = Scheme_sign_offline(sch, keypair, signsess, sig);
//        timerstop();soff=getus();
        c1 = clock();soff=c1-c0;;

        assert(ret >= 0);
        if (breakpoint==1) goto end;

        c2 = clock();
//        timerstart();
        ret = Scheme_sign_online(sch, keypair, signsess, sig, msg, msglen);
//        timerstop();son=getus();
        c3 = clock();son=c3-c2;

        assert(ret >= 0);
        if (breakpoint==2) goto end;

        c4 = clock();
//        timerstart();
        ret = Scheme_vrfy_offline(sch, keypair, vrfysess);
//        timerstop();voff=getus();
        c5 = clock();voff=c5-c4;

        if (ret < 0) return -1;//assert(ret >= 0);
        if (breakpoint==3) goto end;

        c6 = clock();
//        timerstart();
        ret = Scheme_vrfy_online(sch, keypair, vrfysess, sig);
//        timerstop();von=getus();
        c7 = clock();von=c7-c6;

        if (ret < 0) return -1;//assert(ret >= 0);

    end:

        if (warming)
            warming=0;
        else
        {
            if (s_tot) *s_tot += son+soff;
            if (son_tot) *son_tot += son;
            if (von_tot) *von_tot += von;
            if (v_tot) *v_tot += von+voff;
        }

        SignSession_free(signsess);
        VrfySession_free(vrfysess);
        Signature_free(sig);
        free(msg);
    }

    KeyPair_free(keypair);
    return 0;
}

static Scheme * get_scheme_by_id(int schid)
{
    Scheme *sch = NULL;
    switch (schid)
    {
//    case SCHID_AO:
//        sch = Scheme_new(&AOMethods);
//        break;
    case SCHID_ECAO:
        sch = Scheme_new(&ECAO_Methods);
        break;
//    case SCHID_PV:
//        sch = Scheme_new(&PVMethods);
//        break;
    case SCHID_ECPV1:
        sch = Scheme_new(&ECPV1_Methods);
        break;
    case SCHID_ECPV0:
        sch = Scheme_new(&ECPV0_Methods);
        break;
//    case SCHID_OMG:
//        sch = Scheme_new(&OmegaMethods);
//        break;
    case SCHID_ECOMG2:
        sch = Scheme_new(&ECOMG2_Methods);
        break;
    case SCHID_ECOMG1:
        sch = Scheme_new(&ECOMG1_Methods);
        break;
    case SCHID_ECOMG0:
        sch = Scheme_new(&ECOMG0_Methods);
        break;
    }
    return sch;
}


int test(int verbose, int breakpoint, int schid, int bitlen_sec,
    int bitlen_rec, int bitlen_red, int bitlen_clr,
    int sign_count, int user_count,
    clock_t *ret_sign_tot, clock_t *ret_sign_onl,
    clock_t *ret_vrfy_tot, clock_t *ret_vrfy_onl)
{
    Scheme *sch = get_scheme_by_id(schid);
    if (sch == NULL) return -1;

    int ret;

//    KeyPair *keypair = KeyPair_new(sch, bitlen_sec);
//    assert(keypair != NULL);
//
//    ret = KeyPair_gen(keypair);
//    assert(ret == 0);
//
//    SignSession *signsess = SignSession_new(keypair, sch,
//            bitlen_clr, bitlen_rec, bitlen_red);
//    assert(signsess != NULL);
//
//    VrfySession *vrfysess = VrfySession_new(keypair, sch,
//            bitlen_clr, bitlen_rec, bitlen_red);
//    assert(vrfysess != NULL);
//
//    Signature *sig = Signature_new(keypair, sch, bitlen_clr, bitlen_rec, bitlen_red);
//    assert(sig != NULL);

    int i;
    clock_t sign_total = 0;
    clock_t sign_online_total = 0;
    clock_t vrfy_total = 0;
    clock_t vrfy_online_total = 0;

    /* Warm up */
    ret = test_one_user(breakpoint, sign_count, sch,
            //keypair, signsess, vrfysess, sig,
            bitlen_sec,
            bitlen_clr, bitlen_rec, bitlen_red,
            &sign_total, &sign_online_total,
            &vrfy_total, &vrfy_online_total);

    assert(ret >= 0);

    sign_total = 0;
    sign_online_total = 0;
    vrfy_total = 0;
    vrfy_online_total = 0;
    
    int VB=8;
    for (i=1; i<=user_count; i++)
    {
        test_one_user(breakpoint, sign_count, sch,
                //keypair, signsess, vrfysess, sig,
                bitlen_sec,
                bitlen_clr, bitlen_rec, bitlen_red,
                &sign_total, &sign_online_total,
                &vrfy_total, &vrfy_online_total);

//        if (verbose==2&&i==VB) {
//            printf("%d ",i);
//            fflush(stdout);
//            VB*=2;
//        }
    }

    *ret_sign_tot = sign_total;
    *ret_sign_onl = sign_online_total;
    *ret_vrfy_tot = vrfy_total;
    *ret_vrfy_onl = vrfy_online_total;

//    KeyPair_free(keypair);
//    SignSession_free(signsess);
//    VrfySession_free(vrfysess);
//    Signature_free(sig);
    free(sch);
    return 0;
}


const char* getnamebyschid(int schid)
{
    Scheme* sch=get_scheme_by_id(schid);
    const char* ret=Scheme_get_name(sch);
    Scheme_free(sch);
    return ret;
}
