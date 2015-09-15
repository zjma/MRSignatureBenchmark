#include <stddef.h>


void *AO_new_inner()
{
    return NULL;
}

void AO_free_inner(void* inner)
{
    return;
}

char *AO_get_name()
{
    return "OMEGA";
}

int AO_genkey(void* inner, int sec_size)
{
    return 0;
}

int AO_sign_offline(void *inner)
{
    return 0;
}

int AO_sign_online(void *inner, char *msg, int len)
{
    return 0;
}

int AO_vrfy(void *inner)
{
    return 0;
}

