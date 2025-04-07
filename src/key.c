#include "parameter.h"
#include "libbgv.h"
#include "key.h"

void e_skeygen(fmpz_poly_mat_t sk, param_node_t *param)
{
    fmpz *coeffs = _fmpz_vec_init(d);
    fmpz_poly_t poly;
    fmpz_poly_init(poly);
    fmpz_poly_set_coeff_si(poly, 0, 1);
    fmpz_poly_set(fmpz_poly_mat_entry(sk, 0, 0), poly);
    long i;
    for (i = 1; i <= param->n; i++)
    {
        guassian_poly(coeffs, fmpz_poly_mat_entry(sk, i, 0));
        fmpz_poly_scalar_smod_fmpz(fmpz_poly_mat_entry(sk, i, 0), fmpz_poly_mat_entry(sk, i, 0), param->q);
    }

    _fmpz_vec_clear(coeffs, d);
    fmpz_poly_clear(poly);
}

void e_pkeygen(fmpz_poly_mat_t pk, param_node_t *param, fmpz_poly_mat_t sk)
{
    fmpz_poly_mat_t ppk, ee, bb, ss, tmp, tmp1;
    fmpz_poly_mat_init(ppk, param->bign, param->n);
    fmpz_poly_mat_init(ee, param->bign, 1);
    fmpz_poly_mat_init(bb, param->bign, 1);
    fmpz_poly_mat_init(ss, param->n, 1);
    fmpz *coeffs = _fmpz_vec_init(d);

    long i, j;
    for (i = 0; i < param->n; i++)
    {
        fmpz_poly_set(fmpz_poly_mat_entry(ss, i, 0), fmpz_poly_mat_entry(sk, i + 1, 0));
    }
    for (i = 0; i < param->bign; i++)
    {
        guassian_poly(coeffs, fmpz_poly_mat_entry(ee, i, 0));
    }
    for (i = 0; i < param->bign; i++)
    {
        for (j = 0; j < param->n; j++)
        {
            unif_poly(fmpz_poly_mat_entry(ppk, i, j), param->q);
        }
    }
    fmpz_poly_mat_init(tmp, param->bign, 1);
    fmpz_poly_mat_init(tmp1, param->bign, 1);
    fmpz_poly_mat_mul(tmp, ppk, ss);
    fmpz_poly_mat_scalar_mul_fmpz(tmp1, ee, t);
    fmpz_poly_mat_add(bb, tmp, tmp1);
    for (i = 0; i < param->bign; i++)
    {
        fmpz_poly_set(fmpz_poly_mat_entry(pk, i, 0), fmpz_poly_mat_entry(bb, i, 0));
    }
    for (i = 0; i < param->bign; i++)
    {
        for (j = 1; j <= param->n; j++)
        {
            fmpz_poly_neg(fmpz_poly_mat_entry(pk, i, j), fmpz_poly_mat_entry(ppk, i, j - 1));
        }
    }
    for (i = 0; i < param->bign; i++)
    {
        for (j = 0; j < param->n + 1; j++)
        {
            fmpz_poly_rem_basecase(fmpz_poly_mat_entry(pk, i, j), fmpz_poly_mat_entry(pk, i, j), fx);
            fmpz_poly_scalar_smod_fmpz(fmpz_poly_mat_entry(pk, i, j), fmpz_poly_mat_entry(pk, i, j), param->q);
        }
    }
    _fmpz_vec_clear(coeffs, d);
    fmpz_poly_mat_clear(tmp);
    fmpz_poly_mat_clear(tmp1);
    fmpz_poly_mat_clear(ee);
    fmpz_poly_mat_clear(ss);
    fmpz_poly_mat_clear(bb);
    fmpz_poly_mat_clear(ppk);
}

key_node_t *hcrypt_bgv_keygen(key_node_t *kn, param_node_t *param)
{
    sk_node_t *sh;
    pk_node_t *ph;
    sh = (sk_node_t *)malloc(sizeof(sk_node_t));
    fmpz_poly_mat_init(sh->sk, 1 + param->n, 1);

    e_skeygen(sh->sk, param);
    // printf("sk is : \n");
    // fmpz_poly_mat_print(sh->sk,"x");
    sh->next = NULL;
    ph = (pk_node_t *)malloc(sizeof(pk_node_t));
    fmpz_poly_mat_init(ph->pkb, 1, 1);
    fmpz_poly_mat_zero(ph->pkb);
    fmpz_poly_mat_init(ph->pka, param->bign, 1 + (param->n));
    e_pkeygen(ph->pka, param, sh->sk);
    // printf("pk is : \n");
    // fmpz_poly_mat_print(ph->pka,"x");

    fmpz_poly_mat_t s1, s2, tensor;
    long row1, row2, len;
    ph->next = NULL;
    param_node_t *pam, *pamm;
    sk_node_t *ss, *sr;
    pk_node_t *ps, *pr;
    ss = sh;
    ps = ph;
    int l = bgv_get_level() - 1;
    int i;
    pamm = param;
    pam = param->next;
    for (i = l; i >= 0; i--)
    {
        sr = (sk_node_t *)malloc(sizeof(sk_node_t));
        fmpz_poly_mat_init(sr->sk, 1 + pam->n, 1);

        long llog = fmpz_clog(pam->q, t);
        e_skeygen(sr->sk, pam);

        pr = (pk_node_t *)malloc(sizeof(pk_node_t));
        fmpz_poly_mat_init(pr->pka, pam->bign, 1 + (pam->n));
        e_pkeygen(pr->pka, pam, sr->sk);
        // fmpz_poly_mat_print(sr->sk, "p");

        row1 = fmpz_poly_mat_nrows(ss->sk);
        row2 = row1 * row1;
        fmpz_poly_mat_init(tensor, row2, 1);
        vec_tensor(tensor, ss->sk, pamm->q);
        // fmpz_poly_mat_print(tensor, "r");
        len = fmpz_clog(pamm->q, t);
        row2 = row2 * len;
        fmpz_poly_mat_init(s1, row2, 1);
        fmpz_poly_mat_init(s2, row2, 1);
        bitdecomp(s1, tensor, pamm->q);
        //  fmpz_poly_mat_print(s1, "d");
        scale(s2, s1, pamm->q, pam->q, t);

        //  fmpz_poly_mat_print(s2,"y");
        row1 = fmpz_poly_mat_nrows(s2) * llog;
        row2 = fmpz_poly_mat_nrows(sr->sk);
        fmpz_poly_mat_init(pr->pkb, row1, row2);

        switchkeygen(pr->pkb, s2, sr->sk, pam->q);
        //   fmpz_poly_mat_print(pr->pkb, "k");
        fmpz_poly_mat_clear(s1);
        fmpz_poly_mat_clear(s2);
        fmpz_poly_mat_clear(tensor);
        pam = pam->next;
        pamm = pamm->next;
        ss->next = sr;
        ss = sr;

        ps->next = pr;
        ps = pr;
    }
    ss->next = NULL;
    ps->next = NULL;
    kn->prvkey = sh;
    kn->pubkey = ph;
    return kn;
}

void switchkeygen(fmpz_poly_mat_t mapb, fmpz_poly_mat_t s1, fmpz_poly_mat_t s2, fmpz_t qq)
{
    fmpz_poly_mat_t sp1;
    param_node_t *param;
    param = (param_node_t *)malloc(sizeof(param_node_t));
    long n1, n2, i;
    n1 = fmpz_poly_mat_nrows(s1);
    n2 = fmpz_poly_mat_nrows(s2);
    param->n = n2 - 1;
    param->bign = n1 * fmpz_clog(qq, t);
    fmpz_init_set(param->q, qq);
    param->next = NULL;
    e_pkeygen(mapb, param, s2);
    long s1row = fmpz_poly_mat_nrows(s1);
    long len = fmpz_clog(qq, t);
    long qrow = s1row * len;
    powers(sp1, s1, qq);
    for (i = 0; i < param->bign; i++)
    {
        fmpz_poly_add(fmpz_poly_mat_entry(mapb, i, 0), fmpz_poly_mat_entry(mapb, i, 0), fmpz_poly_mat_entry(sp1, i, 0));
        fmpz_poly_rem_basecase(fmpz_poly_mat_entry(mapb, i, 0), fmpz_poly_mat_entry(mapb, i, 0), fx);
        fmpz_poly_scalar_smod_fmpz(fmpz_poly_mat_entry(mapb, i, 0), fmpz_poly_mat_entry(mapb, i, 0), qq);
    }
    fmpz_poly_mat_clear(sp1);
    free(param);
}