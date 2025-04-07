#ifndef LIBBGV_H
#define LIBBGV_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <gmp.h>
#include "flint/fmpz_vec.h"
#include "flint/fmpz_poly.h"
#include "flint/fmpz_poly_mat.h"
#include "flint/fmpz.h"
#include "flint/fmpz_mat.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct pk_node_t
    {
        fmpz_poly_mat_t pka;
        fmpz_poly_mat_t pkb;
        struct pk_node_t *next;
    } pk_node_t;

    typedef struct sk_node_t
    {
        fmpz_poly_mat_t sk;
        struct sk_node_t *next;
    } sk_node_t;

    typedef struct key_node_t
    {
        pk_node_t *pubkey;
        sk_node_t *prvkey;
    } key_node_t;

    typedef struct param_node_t
    {
        fmpz_t q;
        long n;
        long bign;
        struct param_node_t *next;
    } param_node_t;

    typedef struct ciphertext_t
    {
        fmpz_poly_mat_t text;
        int lv;
    } ciphertext_t;
    extern const double pi;
    extern long secparam, d;
    /* denote d in fx */
    extern double dvn;
    /* standard deviation of Guassian distribution*/
    extern fmpz_t bound, t;
    extern fmpz_poly_t fx;
    extern int bgv_level;
    /* for R = Z[x]/(x^d + 1); fx = x^d + 1 */
    extern long chrnd;

    void set_mspace(long vt);       //
    long get_mspace();              //
    void bgv_set_d(long td);        //
    long bgv_get_d();               //
    void bgv_set_secparam(long sp); //
    long bgv_get_secparam();        //
    void bgv_set_dvn(double tdvn);  //
    double bgv_get_dvn();           //
    void bgv_set_bound(int vb);     //
    void bgv_vars_init();           //
    void bgv_vars_clear();          //
    void bgv_set_level(int l);      //
    int bgv_get_level();            //

#ifdef __cplusplus
}
#endif
#endif