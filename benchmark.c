#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <sys/times.h>
#include "scheme.h"

int test_one(Scheme* sch, clock_t *s_tot, clock_t *son_tot, clock_t *v_tot)
{
    int ret;
    clock_t c0,c1,c2,c3,c4,c5;
    struct tms t0,t1,t2,t3,t4,t5;
    char msg[128];
    
    c0 = clock();
    times(&t0);
    ret = Scheme_sign_offline(sch);
    times(&t1);
    c1 = clock();

    assert(ret >= 0);

    c2 = clock();
    times(&t2);
    ret = Scheme_sign_online(sch, msg);
    times(&t3);
    c3 = clock();

    assert(ret >= 0);
    
    c4 = clock();
    times(&t4);
    ret = Scheme_verify(sch);
    times(&t5);
    c5 = clock();
    
    assert(ret >= 0);
    
    c0 = t0.tms_utime;
    c1 = t1.tms_utime;
    c2 = t2.tms_utime;
    c3 = t3.tms_utime;
    c4 = t4.tms_utime;
    c5 = t5.tms_utime;
    *s_tot += c1-c0+c3-c2;
    *son_tot += c3-c2;
    *v_tot += c5-c4;
    
    return 0;
}

int test(Scheme* sch, int sign_count)
{
    int ret;
    
    int i;
    clock_t sign_total = 0;
    clock_t sign_online_total = 0;
    clock_t vrfy_total = 0;
    for (i=0; i<sign_count; i++)
    {
        ret = test_one(sch, &sign_total, &sign_online_total, &vrfy_total);
        assert(ret >= 0);
    }

    char *name = Scheme_get_name(sch);
    assert(name != NULL);

    printf("\nResults for %d %s:\n"
            "Sign tot:        %d\n"
            "Sign online tot: %d\n"
            "Vrfy tot:        %d\n",
            sign_count,
            name,
            (int)sign_total,
            (int)sign_online_total,
            (int)vrfy_total);

    return 0;
}


