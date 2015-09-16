#include <stddef.h>


void *PV_new_inner(int sec_size, int rec_len, int red_len)
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

int PV_sign_offline(void *inner)
{
    return 0;
}

int PV_sign_online(void *inner, char *msg)
{
    return 0;
}

int PV_vrfy(void *inner)
{
    return 0;
}

