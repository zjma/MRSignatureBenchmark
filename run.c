#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "scheme.h"
#include "benchmark.h"

int main(int argc, char **argv)
{
    int i;

    int sec = 1024;
    int rec = 150;
    int schi = SCHEME_OMEGA;
    int sigcount = 1000;
    
    for (i=1; i<argc; i++)
    {
        if (strcmp(argv[i], "-sec") == 0)
        {
            assert(i<argc-1);
            i++;
            sec = atoi(argv[i]);
            assert(sec == 1024 || sec == 2048);
        }
        else if (strcmp(argv[i], "-reclen") == 0)
        {
            assert(i<argc-1);
            i++;
            rec = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-sigcount") == 0)
        {
            assert(i<argc-1);
            i++;
            sigcount = atoi(argv[i]);
            assert(sigcount > 0);
        }
        else
        {
            if (strcmp(argv[i], "ao") == 0)
                schi = SCHEME_AO;
            else if (strcmp(argv[i], "pv") == 0)
                schi = SCHEME_PV;
            else if (strcmp(argv[i], "omega") == 0)
                schi = SCHEME_OMEGA;
            else
                assert(0);
        }
        
    }
    Scheme *sch = Scheme_new(&OmegaMethods);
    assert(sch != NULL);
    
    int red = rec;

    test(sch, sec, rec, red, sigcount);
}

