#include <stddef.h>


void *PV_new_inner()
{
    return NULL;
}

void PV_free_inner(void* inner)
{
    return;
}

char *PV_get_name()
{
    return "OMEGA";
}

int PV_genkey(void* inner, int sec_size)
{
    return 0;
}

int PV_sign_offline(void *inner)
{
    return 0;
}

int PV_sign_online(void *inner, char *msg, int len)
{
    return 0;
}

int PV_vrfy(void *inner)
{
    return 0;
}

