#include "libbgv.h"

int main()
{
    key_node_t *keylist;

    bgv_vars_init();
    bgv_set_bound(1);
    bgv_set_dvn(8.0);
    set_mspace(2);
    fmpz_poly_t ms, mr, mt, my;
    fmpz_poly_init(ms);
    fmpz_poly_init(my);
    fmpz_poly_init(mr);
    fmpz_poly_init(mt);

    fmpz_poly_set_str(ms, "5  0 1 0 0 1");
    fmpz_poly_set_str(mt, "2  0 1");

    param_node_t *param, *r, *w;
    param = param_node_init(param);
    r = param_node_init(r);
    w = param_node_init(w);
    param->n = 1;
    param->bign = 15;
    fmpz_set_si(param->q, 18);
    param->next = r;
    r->n = 1;
    r->bign = 9;
    fmpz_set_si(r->q, 6);
    w->n = 1;
    w->bign = 6;
    fmpz_set_si(w->q, 2);
    r->next = w;
    w->next = NULL;

    /* param->n = 10;
     param->bign = 105;
     fmpz_set_si(param->q, 18);
     param->next = r;
     r->n = 6;
     r->bign = 39;
     fmpz_set_si(r->q, 6);
     w->n = 4;
     w->bign = 18;
     fmpz_set_si(w->q, 2);
     r->next = w;
     w->next = NULL;*/
    // param = hcrypt_bgv_setup(4, 2, 0, param);
    bgv_set_level(2);
    bgv_set_d(16);
    fmpz_poly_set_coeff_ui(fx, 16, 1);
    fmpz_poly_set_coeff_ui(fx, 0, 1);

    printf("%ld\n", bgv_get_d());

    keylist = (key_node_t *)malloc(sizeof(key_node_t));
    keylist = hcrypt_bgv_keygen(keylist, param);
    ciphertext_t *ct, *nct, *ct1, *nct1, *ct_add;

    ct = hcrypt_bgv_encrypt(ct, param, keylist->pubkey, ms);
    ct1 = hcrypt_bgv_encrypt(ct1, param, keylist->pubkey, mt);


    nct = hcrypt_bgv_mul(nct, param, keylist->pubkey, ct, ct1);
    hcrypt_bgv_decrypt(my, param, keylist->prvkey, nct);
    printf("计算 ct * ct1 (9*2) = \n");
    fmpz_poly_print(my);
    printf("\n");

    ct_add = hcrypt_bgv_add(ct_add, param, keylist->pubkey, ct, ct1);
    hcrypt_bgv_decrypt(my, param, keylist->prvkey, ct_add);
    printf("计算 ct + ct1 (9+2)= \n");
    fmpz_poly_print(my);
    printf("\n");

    nct1 = hcrypt_bgv_mul(nct1, param, keylist->pubkey, ct_add, nct);

    hcrypt_bgv_decrypt(mr, param, keylist->prvkey, nct1);
    printf("计算 nct1 = (ct+ct1)*ct*ct1 = (9+2)*9*2 = \n");
    fmpz_poly_print(mr);
    printf("\nover.....  \n");
    fmpz_poly_clear(ms);
    fmpz_poly_clear(mt);
    fmpz_poly_clear(mr);
    fmpz_poly_clear(my);
    free(ct);
    free(ct1);
    free(nct);
    free(nct1);
    bgv_vars_clear();
    return 0;
}