#ifndef __SCHEME_H__
#define __SCHEME_H__

#define SCHEME_OMEGA    0
#define SCHEME_AO       1
#define SCHEME_PV       2

typedef struct SchemeMethods SchemeMethods;
struct SchemeMethods
{
    void *(*new_inner)(int sec_size, int rec_len, int red_len);
    void (*free_inner)(void* inner);
    char *(*get_name)();
    int (*sign_offline)(void *inner);
    int (*sign_online)(void *inner, char *msg);
    int (*vrfy)(void *inner);
};

extern SchemeMethods OmegaMethods;
extern SchemeMethods AOMethods; 
extern SchemeMethods PVMethods;

typedef struct Scheme Scheme;

Scheme *Scheme_new(SchemeMethods *methods, int sec, int rec, int red);

int Scheme_gen_key(Scheme *sch, int sec_size);

char *Scheme_get_name(Scheme *sch);

int Scheme_sign_offline(Scheme *sch);

int Scheme_sign_online(Scheme *sch, char *msg);

int Scheme_verify(Scheme *sch);

#endif
