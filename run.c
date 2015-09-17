#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "scheme.h"
#include "benchmark.h"
#include "locals.h"

int main(int argc, char **argv)
{
    int i;

    int sec = 1024;
    int rec = 512;
    int red = 512;
    SchemeMethods *schm = &OmegaMethods;
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
            assert(sigcount > 0);
        }
        else
        {
            if (strcmp(argv[i], "ao") == 0)
                schm = &AOMethods;
            else if (strcmp(argv[i], "pv") == 0)
                schm = &PVMethods;
            else if (strcmp(argv[i], "omega") == 0)
                schm = &OmegaMethods;
            else
                assert(0);
        }
        
    }

    InitCrypt();

    Scheme *sch = Scheme_new(schm, sec, rec, red);
    assert(sch != NULL);
    
    test(sch, sigcount);
}

