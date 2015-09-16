#include <stddef.h>


void *AO_new_inner(int sec_size, int rec_len, int red_len)
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

int AO_sign_offline(void *inner)
{
    return 0;
}

int AO_sign_online(void *inner, char *msg)
{
    return 0;
}

int AO_vrfy(void *inner)
{
    return 0;
}

