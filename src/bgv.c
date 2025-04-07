#include "parameter.h"
#include "libbgv.h"

ciphertext_t *hcrypt_bgv_mul(ciphertext_t *c, param_node_t *param, pk_node_t *pbk, ciphertext_t *c1, ciphertext_t *c2)
{
    c = (ciphertext_t *)malloc(sizeof(ciphertext_t));
    pk_node_t *pktmp;
    pktmp = pbk;
    param_node_t *hp;
    hp = param;

    int l1 = c1->lv, l2 = c2->lv, l, high, low;
    fmpz_poly_mat_t levhigh, levlow;
    if (l1 >= l2)
    {
        fmpz_poly_mat_init_set(levhigh, c1->text);
        fmpz_poly_mat_init_set(levlow, c2->text);
        high = l1;
        low = l2;
    }
    else
    {
        fmpz_poly_mat_init_set(levhigh, c2->text);
        fmpz_poly_mat_init_set(levlow, c1->text);
        high = l2;
        low = l1;
    }
    l = bgv_get_level();
    c->lv = low - 1;
    // printf("c->lv = %d\n", c->lv);

    while (l > high)
    {
        pktmp = pktmp->next;
        hp = hp->next;
        l--;
    }
    pktmp = pktmp->next;
    l--;

    fmpz_poly_mat_t ctmp, tmpp;
    while (l >= low)
    {
        fmpz_poly_mat_init(ctmp, 1 + hp->next->n, 1);
        long ltmp = fmpz_poly_mat_nrows(levhigh), k;
        fmpz_poly_mat_init(tmpp, ltmp * ltmp, 1);
        fmpz_poly_mat_zero(tmpp);
        for (k = 0; k < ltmp; k++)
        {
            fmpz_poly_set(fmpz_poly_mat_entry(tmpp, k, 0), fmpz_poly_mat_entry(levhigh, k, 0));
        }
        hcrypt_bgv_refresh(ctmp, tmpp, pktmp->pkb, hp->q, hp->next->q, t);
        fmpz_poly_mat_swap(ctmp, levhigh);
        fmpz_poly_mat_clear(ctmp);
        fmpz_poly_mat_clear(tmpp);
        /* sk_node_t *r;
         r = keylist->prvkey;
         int le = bgv_get_level();
         while(le > l) {
                 r = r->next;
                 le--;
         }
         fmpz_poly_t ms;
         fmpz_poly_init(ms);
         e_decrypt(ms, hp->next, r->sk, levhigh);
         fmpz_poly_print(ms);
         printf("\n");*/
        pktmp = pktmp->next;
        hp = hp->next;
        l--;
    }
    fmpz_poly_mat_t c3;
    long row1 = fmpz_poly_mat_nrows(levhigh);
    long row2 = fmpz_poly_mat_nrows(levlow);
    long row = row1 * row2;
    fmpz_poly_mat_init(c3, row, 1);
    long i, j;

    for (i = 0; i < row1; i++)
    {
        for (j = 0; j < row2; j++)
        {
            fmpz_poly_mul(fmpz_poly_mat_entry(c3, j + i * row1, 0), fmpz_poly_mat_entry(levhigh, i, 0), fmpz_poly_mat_entry(levlow, j, 0));
            fmpz_poly_rem_basecase(fmpz_poly_mat_entry(c3, j + i * row1, 0), fmpz_poly_mat_entry(c3, j + i * row1, 0), fx);
            fmpz_poly_scalar_smod_fmpz(fmpz_poly_mat_entry(c3, j + i * row1, 0), fmpz_poly_mat_entry(c3, j + i * row1, 0), hp->q);
        }
    }
    // printf("mul\n");

    fmpz_poly_mat_init(c->text, hp->next->n + 1, 1);
    hcrypt_bgv_refresh(c->text, c3, pktmp->pkb, hp->q, hp->next->q, t);
    fmpz_poly_mat_clear(levhigh);
    fmpz_poly_mat_clear(levlow);
    return c;
}

ciphertext_t *hcrypt_bgv_add(ciphertext_t *c, param_node_t *param, pk_node_t *pbk, ciphertext_t *c1, ciphertext_t *c2)
{
    c = (ciphertext_t *)malloc(sizeof(ciphertext_t));
    pk_node_t *pktmp;
    pktmp = pbk;
    param_node_t *hp;
    hp = param;
    int l1 = c1->lv, l2 = c2->lv, l, high, low;
    fmpz_poly_mat_t levhigh, levlow;
    if (l1 >= l2)
    {
        fmpz_poly_mat_init_set(levhigh, c1->text);
        fmpz_poly_mat_init_set(levlow, c2->text);
        high = l1;
        low = l2;
    }
    else
    {
        fmpz_poly_mat_init_set(levhigh, c2->text);
        fmpz_poly_mat_init_set(levlow, c1->text);
        high = l2;
        low = l1;
    }
    l = bgv_get_level();
    c->lv = low - 1;
    // printf("c->lv = %d\n", c->lv);
    while (l > high)
    {
        pktmp = pktmp->next;
        hp = hp->next;
        l--;
    }
    pktmp = pktmp->next;
    l--;

    fmpz_poly_mat_t ctmp, tmpp;
    // sk_node_t *r;
    // r = keylist->prvkey;
    while (l >= low)
    {
        /* fmpz_poly_t mss;
         fmpz_poly_init(mss);
         e_decrypt(mss, hp, r->sk, levhigh);
         fmpz_poly_print(mss);
         printf("mss\n"); */
        fmpz_poly_mat_init(ctmp, 1 + hp->next->n, 1);
        long ltmp = fmpz_poly_mat_nrows(levhigh), k;
        fmpz_poly_mat_init(tmpp, ltmp * ltmp, 1);
        fmpz_poly_mat_zero(tmpp);
        for (k = 0; k < ltmp; k++)
        {
            fmpz_poly_set(fmpz_poly_mat_entry(tmpp, k, 0), fmpz_poly_mat_entry(levhigh, k, 0));
        }
        hcrypt_bgv_refresh(ctmp, tmpp, pktmp->pkb, hp->q, hp->next->q, t);
        fmpz_poly_mat_swap(ctmp, levhigh);
        fmpz_poly_mat_clear(ctmp);
        fmpz_poly_mat_clear(tmpp);

        /* fmpz_poly_t ms;
         fmpz_poly_init(ms);
         e_decrypt(ms, hp->next, r->next->sk, levhigh);
         fmpz_poly_print(ms);
         printf("ms\n");*/
        pktmp = pktmp->next;
        hp = hp->next;
        l--;
    }

    fmpz_poly_mat_t c3, c4;
    long row1 = fmpz_poly_mat_nrows(levhigh), row2 = fmpz_poly_mat_nrows(levlow), row;
    if (row1 > row2)
        row = row1;
    else
        row = row2;
    fmpz_poly_mat_init(c4, row, 1);
    fmpz_poly_mat_init(c3, row * row, 1);
    fmpz_poly_mat_zero(c3);
    fmpz_poly_mat_add(c4, levhigh, levlow);
    /* printf("levhigh\n");
       fmpz_poly_mat_print(levhigh, "h");
       printf("levlow\n");
       fmpz_poly_mat_print(levlow, "l");
       fmpz_poly_mat_print(c4, "f");*/
    long i;
    for (i = 0; i < row; i++)
    {
        fmpz_poly_scalar_smod_fmpz(fmpz_poly_mat_entry(c4, i, 0), fmpz_poly_mat_entry(c4, i, 0), hp->q);
        fmpz_poly_set(fmpz_poly_mat_entry(c3, i, 0), fmpz_poly_mat_entry(c4, i, 0));
    }
    fmpz_poly_mat_init(c->text, 1 + hp->next->n, 1);
    hcrypt_bgv_refresh(c->text, c3, pktmp->pkb, hp->q, hp->next->q, t);
    // printf("add\n");
    fmpz_poly_mat_clear(levhigh);
    fmpz_poly_mat_clear(levlow);
    return c;
}

void hcrypt_bgv_refresh(fmpz_poly_mat_t c3, fmpz_poly_mat_t c, fmpz_poly_mat_t map, fmpz_t qq, fmpz_t pp, fmpz_t r)
{
    fmpz_poly_mat_t c1;
    powers(c1, c, qq);
    fmpz_poly_mat_t c2;
    long row, col, len;
    row = fmpz_poly_mat_nrows(c1);
    col = fmpz_poly_mat_ncols(c1);
    fmpz_poly_mat_init(c2, row, col);
    scale(c2, c1, qq, pp, r);
    switchkey(c3, map, c2, pp);

    fmpz_poly_mat_clear(c1);
    fmpz_poly_mat_clear(c2);
}

void switchkey(fmpz_poly_mat_t c3, fmpz_poly_mat_t mapb, fmpz_poly_mat_t c1, fmpz_t qq)
{
    fmpz_poly_mat_t bd, bdt;
    long c1row = fmpz_poly_mat_nrows(c1);
    long len = fmpz_clog(qq, t);
    long qrow = c1row * len;
    fmpz_poly_mat_init(bd, qrow, 1);
    bitdecomp(bd, c1, qq);
    long bdtrow, bdtcol, i, j;
    bdtrow = fmpz_poly_mat_ncols(bd);
    bdtcol = fmpz_poly_mat_nrows(bd);
    fmpz_poly_mat_init(bdt, bdtrow, bdtcol);
    for (i = 0; i < bdtrow; i++)
    {
        for (j = 0; j < bdtcol; j++)
        {
            fmpz_poly_set(fmpz_poly_mat_entry(bdt, i, j), fmpz_poly_mat_entry(bd, j, i));
        }
    }
    long col = fmpz_poly_mat_ncols(mapb);
    fmpz_poly_mat_mul(c3, bdt, mapb);
    for (i = 0; i < bdtrow; i++)
    {
        for (j = 0; j < col; j++)
        {
            fmpz_poly_rem_basecase(fmpz_poly_mat_entry(c3, i, j), fmpz_poly_mat_entry(c3, i, j), fx);
            fmpz_poly_scalar_smod_fmpz(fmpz_poly_mat_entry(c3, i, j), fmpz_poly_mat_entry(c3, i, j), qq);
        }
    }
    fmpz_poly_mat_clear(bd);
    fmpz_poly_mat_clear(bdt);
}

void hcrypt_bgv_decrypt(fmpz_poly_t ms, param_node_t *param, sk_node_t *tmp, ciphertext_t *ct)
{
    // printf("decrypt\n");
    param_node_t *pam;
    pam = param;

    int i = bgv_get_level();
    ;

    while (i > ct->lv)
    {
        tmp = tmp->next;
        pam = pam->next;
        i--;
    }
    fmpz_poly_init(ms);
    e_decrypt(ms, pam, tmp->sk, ct->text);
}

ciphertext_t *hcrypt_bgv_encrypt(ciphertext_t *ct, param_node_t *param, pk_node_t *pkey, fmpz_poly_t ms)
{
    ct = (ciphertext_t *)malloc(sizeof(ciphertext_t));
    ct->lv = bgv_get_level();
    fmpz_poly_mat_init(ct->text, 1 + param->n, 1);
    e_encrypt(ct->text, param, pkey->pka, ms);
    // printf("encrypt\n");
    // fmpz_poly_mat_print(ct->text, "r");
    return ct;
}

param_node_t *hcrypt_bgv_setup(int lamda, int level, int b, param_node_t *param)
{
    bgv_set_level(level);
    fmpz_t mult;
    fmpz_set_ui(mult, lamda * level);
    int miu;
    miu = (int)fmpz_flog(mult, t);

    int high;
    high = (level + 1) * miu;
    hcrypt_random(param->q, high);
    fmpz_t tmp;
    fmpz_init(tmp);
    fmpz_fdiv_q(tmp, param->q, bound);
    long prod;
    prod = lamda * fmpz_flog(tmp, t);

    if (b == 0)
    {
        param->n = prod;
        d = 1;
    }
    else
    {
        param->n = 1;
        d = prod;
    }
    param->bign = ceil((2 * param->n + 1) * fmpz_flog(param->q, t));
    fmpz_poly_set_coeff_ui(fx, d, 1);
    fmpz_poly_set_coeff_ui(fx, 0, 1);
    param_node_t *r, *pn;

    r = param;
    int j;
    for (j = level - 1; j >= 0; j--)
    {
        pn = e_setup((j + 1) * miu, lamda, b, pn);
        r->next = pn;
        r = pn;
    }
    r->next = NULL;

    fmpz_clear(tmp);
    return param;
}

void scale(fmpz_poly_mat_t c2, fmpz_poly_mat_t c1, fmpz_t qq, fmpz_t pp, fmpz_t r)
{
    // printf("before scale\n");
    // fmpz_poly_mat_print(c1, "x");
    long row, col, i, j, len, k;
    row = fmpz_poly_mat_nrows(c1);
    col = fmpz_poly_mat_ncols(c1);
    fmpz_poly_t poly;
    fmpz_poly_init(poly);
    fmpz_t coeff, tmp, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6;
    fmpz_init(coeff);
    fmpz_init(tmp);
    fmpz_init(tmp1);
    fmpz_init(tmp2);
    fmpz_init(tmp3);
    fmpz_init(tmp4);
    fmpz_init(tmp5);
    fmpz_init(tmp6);

    for (i = 0; i < row; i++)
    {
        for (j = 0; j < col; j++)
        {
            fmpz_poly_set(poly, fmpz_poly_mat_entry(c1, i, j));
            len = fmpz_poly_length(poly);
            for (k = 0; k < len; k++)
            {
                fmpz_poly_get_coeff_fmpz(tmp, poly, k);
                fmpz_mod(tmp1, tmp, r); /* tmp1 = base = tmp % r */

                if (fmpz_cmp_si(tmp, 0) > 0)
                {
                    fmpz_mul(coeff, tmp, pp);
                    fmpz_fdiv_q(tmp2, coeff, qq);
                    fmpz_fdiv_q(tmp3, tmp2, r);

                    fmpz_mul(tmp4, tmp3, r);
                    fmpz_add(tmp5, tmp4, tmp1);
                    fmpz_poly_set_coeff_fmpz(poly, k, tmp5);
                }
                else if (fmpz_cmp_si(tmp, 0) < 0)
                {
                    fmpz_neg(tmp2, tmp);
                    fmpz_mul(coeff, tmp2, pp);
                    fmpz_fdiv_q(tmp3, coeff, qq);
                    fmpz_fdiv_q(tmp4, tmp3, r);
                    fmpz_mul(tmp5, tmp4, r);
                    fmpz_sub(tmp6, tmp1, tmp5);
                    fmpz_poly_set_coeff_fmpz(poly, k, tmp6);
                }
                else
                {
                    fmpz_poly_set_coeff_fmpz(poly, k, tmp1);
                }
            }
            fmpz_poly_set(fmpz_poly_mat_entry(c2, i, j), poly);
        }
    }
    fmpz_poly_clear(poly);
    fmpz_clear(coeff);
    fmpz_clear(tmp);
    fmpz_clear(tmp1);
    fmpz_clear(tmp2);
    fmpz_clear(tmp3);
    fmpz_clear(tmp4);
    fmpz_clear(tmp5);
    fmpz_clear(tmp6);
    // printf("after scale\n");
    // fmpz_poly_mat_print(c2, "x");
}

void vec_tensor(fmpz_poly_mat_t tensor, fmpz_poly_mat_t x, fmpz_t qq)
{
    long row1 = fmpz_poly_mat_nrows(x);

    long i, j;
    for (i = 0; i < row1; i++)
    {
        for (j = 0; j < row1; j++)
        {
            fmpz_poly_mul(fmpz_poly_mat_entry(tensor, j + i * row1, 0), fmpz_poly_mat_entry(x, i, 0), fmpz_poly_mat_entry(x, j, 0));
            fmpz_poly_rem_basecase(fmpz_poly_mat_entry(tensor, j + i * row1, 0), fmpz_poly_mat_entry(tensor, j + i * row1, 0), fx);
            fmpz_poly_scalar_smod_fmpz(fmpz_poly_mat_entry(tensor, j + i * row1, 0), fmpz_poly_mat_entry(tensor, j + i * row1, 0), qq);
        }
    }
}

param_node_t *e_setup(int miu, int lamda, int b, param_node_t *param)
{
    param = param_node_init(param);
    hcrypt_random(param->q, miu);
    fmpz_t tmp;
    fmpz_init(tmp);
    fmpz_fdiv_q(tmp, param->q, bound);
    long prod;
    prod = lamda * fmpz_flog(tmp, t);

    if (b == 0)
    {
        param->n = prod;
    } /* LWE */
    else
    {
        param->n = 1;
    } /* RLWE */

    param->bign = ceil((2 * param->n + 1) * fmpz_flog(param->q, t));

    fmpz_clear(tmp);
    return param;
}

void e_encrypt(fmpz_poly_mat_t ct, param_node_t *param, fmpz_poly_mat_t pk, fmpz_poly_t ms)
{
    long i, j;
    fmpz_poly_mat_t mm, rr, tmp, tmp1;
    fmpz_poly_mat_init(mm, 1 + param->n, 1);
    fmpz_poly_mat_init(rr, param->bign, 1);
    fmpz_poly_mat_init(tmp, 1 + param->n, 1);
    fmpz_poly_mat_init(tmp1, 1 + (param->n), param->bign);
    for (i = 0; i < 1 + param->n; i++)
    {
        for (j = 0; j < param->bign; j++)
        {
            fmpz_poly_set(fmpz_poly_mat_entry(tmp1, i, j), fmpz_poly_mat_entry(pk, j, i));
        }
    }
    fmpz_poly_mat_zero(mm);
    fmpz_poly_set(fmpz_poly_mat_entry(mm, 0, 0), ms);

    for (i = 0; i < param->bign; i++)
    {
        unif_poly(fmpz_poly_mat_entry(rr, i, 0), t);
    }
    fmpz_poly_mat_mul(tmp, tmp1, rr);
    fmpz_poly_mat_add(ct, mm, tmp);

    for (i = 0; i < param->n + 1; i++)
    {
        fmpz_poly_rem_basecase(fmpz_poly_mat_entry(ct, i, 0), fmpz_poly_mat_entry(ct, i, 0), fx);
        fmpz_poly_scalar_smod_fmpz(fmpz_poly_mat_entry(ct, i, 0), fmpz_poly_mat_entry(ct, i, 0), param->q);
    }

    fmpz_poly_mat_clear(tmp);
    fmpz_poly_mat_clear(tmp1);
    fmpz_poly_mat_clear(mm);
    fmpz_poly_mat_clear(rr);
}

void e_decrypt(fmpz_poly_t ms, param_node_t *param, fmpz_poly_mat_t sk, fmpz_poly_mat_t ct)
{
    fmpz_poly_t tmp;
    fmpz_poly_init(tmp);
    fmpz_poly_zero(ms);

    long i;

    // fmpz_poly_mat_print(ct, "x");
    // fmpz_poly_mat_print(sk, "x");
    for (i = 0; i < param->n + 1; i++)
    {
        fmpz_poly_mul(tmp, fmpz_poly_mat_entry(ct, i, 0), fmpz_poly_mat_entry(sk, i, 0));
        fmpz_poly_add(ms, ms, tmp);
        // fmpz_poly_print(ms);
        // printf("\n");
    }
    fmpz_poly_rem_basecase(ms, ms, fx);
    // fmpz_poly_print(ms);
    fmpz_poly_scalar_smod_fmpz(ms, ms, param->q);
    // fmpz_poly_print(ms);
    fmpz_poly_scalar_smod_fmpz(ms, ms, t);

    fmpz_poly_clear(tmp);
}

void bitdecomp(fmpz_poly_mat_t dc, fmpz_poly_mat_t x, fmpz_t qq)
{
    long xrow = fmpz_poly_mat_nrows(x);
    long len = fmpz_clog(qq, t);
    // long qrow = xrow * len;
    long i, j, k;
    fmpz_mat_t bits;
    fmpz_mat_init(bits, d, len);
    fmpz_t hold;
    fmpz_init(hold);
    fmpz_poly_t xtmp;
    for (i = 0; i < xrow; i++)
    {
        fmpz_mat_zero(bits);
        for (j = 0; j < d; j++)
        {
            fmpz_poly_get_coeff_fmpz(hold, fmpz_poly_mat_entry(x, i, 0), j);
            k = 0;
            while (!fmpz_is_zero(hold))
            {
                fmpz_mod(fmpz_mat_entry(bits, j, k), hold, t);
                fmpz_tdiv_q(hold, hold, t);

                k++;
            }
        }

        for (j = 0; j < len; j++)
        {
            fmpz_poly_init(xtmp);
            for (k = 0; k < d; k++)
            {
                fmpz_poly_set_coeff_fmpz(xtmp, k, fmpz_mat_entry(bits, k, j));
            }

            fmpz_poly_set(fmpz_poly_mat_entry(dc, i + j * xrow, 0), xtmp);
            fmpz_poly_clear(xtmp);
        }
    }
    fmpz_clear(hold);
    fmpz_mat_clear(bits);
}

void powers(fmpz_poly_mat_t po, fmpz_poly_mat_t x, fmpz_t qq)
{
    long xrow = fmpz_poly_mat_nrows(x);
    long len = fmpz_clog(qq, t);
    long qrow = xrow * len;
    long i, j;
    fmpz_poly_mat_init(po, qrow, 1);
    for (i = 0; i < xrow; i++)
    {
        fmpz_poly_set(fmpz_poly_mat_entry(po, i, 0), fmpz_poly_mat_entry(x, i, 0));
    }
    for (i = 1; i < len; i++)
    {
        for (j = 0; j < xrow; j++)
        {
            fmpz_poly_scalar_mul_fmpz(fmpz_poly_mat_entry(po, j + i * xrow, 0), fmpz_poly_mat_entry(po, j + (i - 1) * xrow, 0), t);
            fmpz_poly_scalar_smod_fmpz(fmpz_poly_mat_entry(po, j + i * xrow, 0), fmpz_poly_mat_entry(po, j + i * xrow, 0), qq);
        }
    }
}
