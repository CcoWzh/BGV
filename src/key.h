#pragma once
#include "parameter.h"

void e_skeygen(fmpz_poly_mat_t sk, param_node_t *param);                                    
void e_pkeygen(fmpz_poly_mat_t pk, param_node_t *param, fmpz_poly_mat_t sk);                
void switchkeygen(fmpz_poly_mat_t mapb, fmpz_poly_mat_t s1, fmpz_poly_mat_t s2, fmpz_t qq); 
key_node_t *hcrypt_bgv_keygen(key_node_t *kn, param_node_t *param);