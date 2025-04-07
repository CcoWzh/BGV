#pragma once
#include "parameter.h"

void hcrypt_random(fmpz_t r, int len);                                                                               //
fmpz *samplez(fmpz *vec);                                                                                            //
void guassian_poly(fmpz *c, fmpz_poly_t poly);                                                                       //
void unif_poly(fmpz_poly_t poly, fmpz_t space);                                                                      //
param_node_t *param_node_init(param_node_t *pnt);                                                                    //
param_node_t *e_setup(int miu, int lamda, int b, param_node_t *param);                                               //
void e_encrypt(fmpz_poly_mat_t ct, param_node_t *param, fmpz_poly_mat_t pk, fmpz_poly_t ms);                         //
void e_decrypt(fmpz_poly_t ms, param_node_t *param, fmpz_poly_mat_t sk, fmpz_poly_mat_t ct);                         //
void bitdecomp(fmpz_poly_mat_t dc, fmpz_poly_mat_t x, fmpz_t qq);                                                    // KeySwitching 方案组成部分
void powers(fmpz_poly_mat_t po, fmpz_poly_mat_t x, fmpz_t qq);                                                       // KeySwitching 方案组成部分
void switchkey(fmpz_poly_mat_t c2, fmpz_poly_mat_t mapb, fmpz_poly_mat_t c1, fmpz_t qq);                             // 密钥切换技术，用于降低密文和密钥的维度。
void scale(fmpz_poly_mat_t c2, fmpz_poly_mat_t c1, fmpz_t qq, fmpz_t pp, fmpz_t r);                                  // 模切换技术，用于降低噪声的绝对大小（相对大小略有上升）
void hcrypt_bgv_refresh(fmpz_poly_mat_t c3, fmpz_poly_mat_t c, fmpz_poly_mat_t map, fmpz_t qq, fmpz_t pp, fmpz_t r); //
param_node_t *hcrypt_bgv_setup(int lamda, int level, int b, param_node_t *param);                                    //
void vec_tensor(fmpz_poly_mat_t tensor, fmpz_poly_mat_t x, fmpz_t qq);                                               //
ciphertext_t *hcrypt_bgv_encrypt(ciphertext_t *ct, param_node_t *param, pk_node_t *pk, fmpz_poly_t ms);
void hcrypt_bgv_decrypt(fmpz_poly_t ms, param_node_t *param, sk_node_t *sk, ciphertext_t *ct);
ciphertext_t *hcrypt_bgv_add(ciphertext_t *c, param_node_t *param, pk_node_t *pbk, ciphertext_t *c1, ciphertext_t *c2);
ciphertext_t *hcrypt_bgv_mul(ciphertext_t *c, param_node_t *param, pk_node_t *pbk, ciphertext_t *c1, ciphertext_t *c2);
