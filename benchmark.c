/**
 * \file benchmark.c
 */

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <time.h>
//#include <sys/times.h>
#include "scheme.h"
#include "benchmark.h"

int test_one(Scheme* sch, int bitlen_sec,
        int bitlen_clr, int bitlen_rec, int bitlen_red,
        clock_t *s_tot, clock_t *son_tot,
        clock_t *v_tot, clock_t *von_tot)
{
    int ret;
    clock_t c0,c1,c2,c3,c4,c5,c6,c7;
    // struct tms t0,t1,t2,t3,t4,t5,t6,t7;

    KeyPair *keypair = KeyPair_new(sch, bitlen_sec);
    assert(keypair != NULL);

    SignSession *signsess = SignSession_new(keypair, sch,
            bitlen_clr, bitlen_rec, bitlen_red);
    assert(signsess != NULL);

    VrfySession *vrfysess = VrfySession_new(sch,
            bitlen_clr, bitlen_rec, bitlen_red);
    assert(vrfysess != NULL);

    Signature *sig = Signature_new(sch, bitlen_clr, bitlen_rec, bitlen_red);
    assert(sig != NULL);

    int msglen = bitlen_rec/8 + bitlen_clr/8;
    char *msg = malloc(msglen);
    assert(msg != NULL);

    c0 = clock();
    // times(&t0);
    ret = Scheme_sign_offline(sch, keypair, signsess, sig);
    // times(&t1);
    c1 = clock();

    assert(ret >= 0);

    c2 = clock();
    // times(&t2);
    ret = Scheme_sign_online(sch, keypair, signsess, sig, msg, msglen);
    // times(&t3);
    c3 = clock();

    assert(ret >= 0);

    c4 = clock();
    // times(&t4);
    ret = Scheme_vrfy_offline(sch, keypair, vrfysess);
    // times(&t5);
    c5 = clock();

    assert(ret >= 0);

    c6 = clock();
    // times(&t6);
    ret = Scheme_vrfy_online(sch, keypair, vrfysess, sig);
    // times(&t7);
    c7 = clock();

    assert(ret >= 0);

    /*
    c0 = t0.tms_utime;
    c1 = t1.tms_utime;
    c2 = t2.tms_utime;
    c3 = t3.tms_utime;
    c4 = t4.tms_utime;
    c5 = t5.tms_utime;
    c6 = t6.tms_utime;
    c7 = t7.tms_utime;
    */
    *s_tot += c1-c0+c3-c2;
    *son_tot += c3-c2;
    *v_tot += c5-c4;
    *von_tot += c7-c6+c5-c4;
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
//    case SCHID_ECAO:
//        sch = Scheme_new(&ECAOMethods);
//        break;
//    case SCHID_PV:
//        sch = Scheme_new(&PVMethods);
//        break;
//    case SCHID_ECPV:
//        sch = Scheme_new(&ECPVMethods);
//        break;
//    case SCHID_OMG:
//        sch = Scheme_new(&OmegaMethods);
//        break;
    case SCHID_ECOMG:
        sch = Scheme_new(&ECOmegaMethods);
        break;
    }
    return sch;
}


int test(int schid, int bitlen_sec,
    int bitlen_rec, int bitlen_red, int bitlen_clr, int sign_count,
    clock_t *ret_sign_tot, clock_t *ret_sign_onl,
    clock_t *ret_vrfy_tot, clock_t *ret_vrfy_onl)
{
    Scheme *sch = get_scheme_by_id(schid);
    if (sch == NULL) return -1;

    int ret;

    int i;
    clock_t sign_total = 0;
    clock_t sign_online_total = 0;
    clock_t vrfy_total = 0;
    clock_t vrfy_online_total = 0;
    /* Warm up */
    ret = test_one(sch, bitlen_sec,
            bitlen_clr, bitlen_rec, bitlen_red,
            &sign_total, &sign_online_total,
            &vrfy_total, &vrfy_online_total);

    assert(ret >= 0);

    sign_total = 0;
    sign_online_total = 0;
    vrfy_total = 0;
    vrfy_online_total = 0;

    for (i=0; i<sign_count; i++)
    {
        ret = test_one(sch, bitlen_sec,
                bitlen_clr, bitlen_rec, bitlen_red,
                &sign_total, &sign_online_total,
                &vrfy_total, &vrfy_online_total);
        assert(ret >= 0);
    }

    // char *name = Scheme_get_name(sch);
    // assert(name != NULL);
    // printf("\nResults for %d %s:\n"
    //         "Sign tot:        %d\n"
    //         "Sign online tot: %d\n"
    //         "Vrfy tot:        %d\n",
    //         sign_count,
    //         name,
    //         (int)sign_total,
    //         (int)sign_online_total,
    //         (int)vrfy_total);
    *ret_sign_tot = sign_total;
    *ret_sign_onl = sign_online_total;
    *ret_vrfy_tot = vrfy_total;
    *ret_vrfy_onl = vrfy_online_total;
    return 0;
}
