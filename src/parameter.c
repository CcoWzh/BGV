// #include "libbgv.h"
#include "parameter.h"

const double pi = 3.1415926;
long secparam, d;
double dvn;
fmpz_t bound, t;
fmpz_poly_t fx;
int bgv_level;
long chrnd;

void set_mspace(long vt)
{
    fmpz_set_ui(t, vt);
}

long get_mspace()
{
    return fmpz_get_ui(t);
}

void bgv_set_d(long td)
{
    d = td;
}

long bgv_get_d()
{
    return d;
}

void bgv_set_level(int l)
{
    bgv_level = l;
}

int bgv_get_level()
{
    return bgv_level;
}

void bgv_set_secparam(long sp)
{
    secparam = sp;
}

long bgv_get_secparam()
{
    return secparam;
}

void bgv_set_dvn(double tdvn)
{
    dvn = tdvn;
}

double bgv_get_dvn()
{
    return dvn;
}

void bgv_set_bound(int vb)
{
    fmpz_set_ui(bound, vb);
}

void bgv_vars_init()
{
    fmpz_init(bound);
    fmpz_init(t);
    fmpz_poly_init(fx);
}

void bgv_vars_clear()
{
    fmpz_clear(bound);
    fmpz_clear(t);
    fmpz_poly_clear(fx);
}

param_node_t *param_node_init(param_node_t *pnt)
{
    pnt = (param_node_t *)malloc(sizeof(param_node_t));
    pnt->next = NULL;
    pnt->n = pnt->bign = 0;
    fmpz_init(pnt->q);
    return pnt;
}

void hcrypt_random(fmpz_t r, int len)
{
    mpz_t tmp;
    FILE *fp;
    int flag = 0;
    mpz_init(tmp);
    fp = fopen("/dev/urandom", "rb");
    if (fp)
    {
        int bytecount, leftover;
        unsigned char *bytes;
        bytecount = (len + 7) / 8;
        leftover = len % 8;
        bytes = (unsigned char *)malloc(bytecount);
        if (fread(bytes, 1, bytecount, fp))
        {

            if (leftover)
            {
                *bytes = *bytes % (1 << leftover);
            }
            mpz_import(tmp, bytecount, 1, 1, 0, 0, bytes);
            flag = 1;
        }
        fclose(fp);
        free(bytes);
    }
    if (!fp || !flag)
    {
        gmp_randstate_t gmpRandState;
        gmp_randinit_default(gmpRandState);
        gmp_randseed_ui(gmpRandState, (unsigned long)time(0) + (chrnd++));
        while (1)
        {
            mpz_urandomb(tmp, gmpRandState, len);
            if (mpz_sizeinbase(tmp, 2) == len)
                break;
        }
        gmp_randclear(gmpRandState);
    }
    fmpz_set_mpz(r, tmp);
    mpz_clear(tmp);
}

fmpz *samplez(fmpz *vec)
{
    long ele = bgv_get_d();
    if (ele == 0)
        return NULL;
    double tdvn = bgv_get_dvn();
    long a = (long)ceil(-10 * tdvn);
    long b = (long)floor(+10 * tdvn);
    long x, i;
    double p;
    int len = sizeof(unsigned long int);
    fmpz_t randseed;
    fmpz_init(randseed);
    hcrypt_random(randseed, len);
    unsigned long int useed = fmpz_get_ui(randseed);
    srand(useed);
    for (i = 0; i < ele; i++)
    {
        do
        {
            x = rand() % (b - a) + a;
            p = exp(-pi * x / (tdvn * tdvn));
        } while (!(p > 0 && p <= 1));

        vec[i] = x;
    }
    fmpz_clear(randseed);
    return vec;
}

void guassian_poly(fmpz *c, fmpz_poly_t poly)
{
    fmpz *tmp = samplez(c);
    long k, ele = bgv_get_d();
    for (k = 0; k < ele; k++)
    {
        fmpz_poly_set_coeff_si(poly, k, tmp[k]);
    }
}

void unif_poly(fmpz_poly_t poly, fmpz_t space)
{
    int i;
    int len = sizeof(unsigned long int);
    fmpz_t randseed;
    fmpz_init(randseed);
    hcrypt_random(randseed, 3 /*len*/);
    unsigned long int useed = fmpz_get_ui(randseed);
    mpz_t rndnum, rndbd;
    fmpz_t rndfmpz;
    gmp_randstate_t gmpstate;

    mpz_init(rndnum);
    mpz_init(rndbd);
    fmpz_get_mpz(rndbd, space);
    fmpz_init(rndfmpz);
    gmp_randinit_default(gmpstate);
    gmp_randseed_ui(gmpstate, useed);

    long ele = bgv_get_d();
    for (i = 0; i < ele; i++)
    {
        mpz_urandomm(rndnum, gmpstate, rndbd);
        fmpz_set_mpz(rndfmpz, rndnum);
        fmpz_poly_set_coeff_fmpz(poly, i, rndfmpz);
    }
    fmpz_clear(randseed);
    fmpz_clear(rndfmpz);
    gmp_randclear(gmpstate);
    mpz_clear(rndnum);
    mpz_clear(rndbd);
}