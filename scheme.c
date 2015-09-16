#include <stddef.h>
#include <stdlib.h>
#include <assert.h>

#include "locals.h"
#include "scheme.h"


struct Scheme
{
    SchemeMethods*  imp;
    void*           inner;
};

Scheme *Scheme_new(SchemeMethods *methods, int sec_size, int rec_len, int red_len)
{
    Scheme *ret = malloc(sizeof(Scheme));
    ret->imp = methods;
    void *inner = methods->new_inner(sec_size, rec_len, red_len);
    if (inner == NULL) goto err;
    ret->inner = inner;
    return ret;
    
err:
    free(ret);
    return NULL;
}

void Scheme_free(Scheme *sch)
{
    if (sch == NULL) return;
    sch->imp->free_inner(sch->inner);
    free(sch);
}

char *Scheme_get_name(Scheme *sch)
{
    return sch->imp->get_name();
}

int Scheme_sign_offline(Scheme *sch)
{
    assert(sch != NULL);
    return sch->imp->sign_offline(sch->inner);
}

int Scheme_sign_online(Scheme *sch, char *msg)
{
    assert(sch != NULL);
    return sch->imp->sign_online(sch->inner, msg);
}

int Scheme_verify(Scheme *sch)
{
    assert(sch != NULL);
    return sch->imp->vrfy(sch->inner);
}

SchemeMethods OmegaMethods = {
    .new_inner = Omega_new_inner,
    .free_inner = Omega_free_inner,
    .get_name = Omega_get_name,
    .sign_offline = Omega_sign_offline,
    .sign_online = Omega_sign_online,
    .vrfy = Omega_vrfy,
};

SchemeMethods AOMethods = {
    .new_inner = AO_new_inner,
    .free_inner = AO_free_inner,
    .get_name = AO_get_name,
    .sign_offline = AO_sign_offline,
    .sign_online = AO_sign_online,
    .vrfy = AO_vrfy,
};


SchemeMethods PVMethods = {
    .new_inner = PV_new_inner,
    .free_inner = PV_free_inner,
    .get_name = PV_get_name,
    .sign_offline = PV_sign_offline,
    .sign_online = PV_sign_online,
    .vrfy = PV_vrfy,
};



