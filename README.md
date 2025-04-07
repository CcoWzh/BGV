本案例的实现，是参考开源库：https://github.com/theSwan/bvbgv/blob/master/hcrypt_bgv.c

# 一、环境准备

## 1.1 安装`FLINT`库

实现BGV算法，先要用到`FLINT`这个快速数论库中的函数。

参考：FLINT：数论快速库：https://flintlib.org/

## 1.2 程序运行

写`CMakeLists.txt`，配置环境：

```cpp
cmake_minimum_required (VERSION 3.5)				# cmake版本最低要求
project (BGVtest)  # 设置工程名称

set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/flint/src)      
FILE(GLOB_RECURSE all_lib ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/flint/*.so) 

# 指定头文件搜索路径
INCLUDE_DIRECTORIES(${SRC}/)
# 指定引用的外部库的搜索路径
LINK_DIRECTORIES(${all_psi_lib} /usr/lib)

# 将src下面的所有头文件路径保存至 all_head_files 数组变量中
# 将src下面的所有源文件路径保存至 all_source_files 数组变量中
FILE(GLOB_RECURSE all_source_files "src/*.cpp" "src/*.c")
FILE(GLOB_RECURSE all_head_files "src/*.hpp" "src*.h")

# 添加可执行文件
add_executable(bgv_test 
              ${all_source_files}
              ${all_head_files})

# 链接库文件
target_link_libraries(bgv_test PUBLIC ${all_lib} m gmp mpfr)
```

运行结果：

```cpp
hui@hui-virtual-machine:~/Desktop/SC-test/bgv-c/build$ ./bgv_test 
计算 ct * ct1 (9*2) = 
6  0 0 1 0 0 1
计算 ct + ct1 (9+2)= 
5  0 0 0 0 1
计算 nct1 = (ct+ct1)*ct*ct1 = (9+2)*9*2 = 
10  0 0 0 0 0 0 1 0 0 1
over.....  
```

# 二、算法实现

## 1.1 理论方案

![img](https://cdn.nlark.com/yuque/0/2025/png/45962731/1743558165669-835087ee-6485-407e-b20c-8f74985000b2.png)

![img](https://cdn.nlark.com/yuque/0/2025/png/45962731/1743558177670-35769f92-2b5d-4773-b1e8-64a4a95baf93.png)       

![img](https://cdn.nlark.com/yuque/0/2025/png/45962731/1743558125633-22e2b960-947e-4f29-bcee-85922895bce1.png)

## 1.2 编程实现

### 结构体定义

```cpp
// 定义 公钥结构体
// 链表结构，对应层级（level），每个level对应其公私钥
typedef struct pk_node_t
{
fmpz_poly_mat_t pka;
fmpz_poly_mat_t pkb;
struct pk_node_t *next;
} pk_node_t;

// 定义 私钥结构体
// 链表结构，对应层级（level），每个level对应其公私钥
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

// 定义 参数的结构体，链表都与level有关
typedef struct param_node_t
{
fmpz_t q;
long n;
long bign;
struct param_node_t *next;
} param_node_t;

// 定义 密文的结构体
typedef struct ciphertext_t
{
fmpz_poly_mat_t text;
int lv;
} ciphertext_t;
```

### 产生公私钥

私钥：

```cpp
sk is : 
<2 x 1 matrix over Z[x]>
[1]
[5*x^15-8*x^14-x^13+4*x^12-3*x^11-6*x^10+x^9-8*x^8-7*x^7+x^5+8*x^4-2*x^3+5*x^2+2*x]
```

公钥：

```cpp
pk is : 
<15 x 2 matrix over Z[x]>
[-x^15-x^14-8*x^13-x^12+3*x^11-2*x^10+7*x^9-x^8-6*x^7-2*x^6-7*x^5+2*x^4+9*x^3-5*x^2+3*x+3, 8*x^15-8*x^14-7*x^13+3*x^12-5*x^11+7*x^10+5*x^9+6*x^8+3*x^7+5*x^6+x^5+7*x^4-2*x^3+3*x^2-7*x+4]
[x^15-5*x^14+x^13-x^12+7*x^11+8*x^10-2*x^8-7*x^7+9*x^6+8*x^5+4*x^4+7*x^3-7*x^2+3*x-3, 8*x^15+8*x^14-7*x^13+7*x^12+x^11-8*x^10-8*x^9+6*x^8-6*x^7+5*x^6+x^5-6*x^4-5*x^2+3*x]
[8*x^15+6*x^14+5*x^13+4*x^12-3*x^11-3*x^10-2*x^9-7*x^8-3*x^7+9*x^6-x^5+5*x^4+x^3+7*x^2-x, -6*x^15+x^14-3*x^13-7*x^12+6*x^11+5*x^10-3*x^9+4*x^8-4*x^7+3*x^6+8*x^5+5*x^4+8*x^3-5*x^2+6*x+7]
[2*x^15-2*x^14+2*x^13-x^12+4*x^11+9*x^10+5*x^9-4*x^7-4*x^6+9*x^5+2*x^4+4*x^3+9*x^2-3*x+8, 9*x^15+5*x^14-3*x^13-3*x^12+5*x^11+3*x^10-2*x^9-8*x^8+2*x^7+4*x^6-5*x^5-2*x^4+8*x^3-2*x^2-x-4]
[x^15-2*x^14+2*x^13+8*x^12-7*x^11-8*x^10+5*x^9-5*x^8-8*x^7-3*x^6+x^5+6*x^4+5*x^3-7*x^2+8*x+8, -3*x^15+9*x^14+x^13-6*x^12+8*x^11-x^10+4*x^9+3*x^8+2*x^7+9*x^6+x^5+3*x^4+4*x^3-5*x^2-8*x+5]
[x^15+9*x^14-5*x^13-3*x^12+x^11+4*x^10-3*x^9+9*x^8+2*x^7-7*x^6+9*x^5+5*x^4+4*x^3+6*x^2+3*x-8, 2*x^15-3*x^14-5*x^13+2*x^12+4*x^10-7*x^9-5*x^8+4*x^7-x^6+4*x^5-2*x^4+9*x^3+3*x^2-x+7]
[-8*x^15-8*x^14-2*x^13-7*x^12-4*x^11+7*x^10-5*x^9-2*x^7+2*x^6+5*x^5-8*x^4-2*x^3+7*x^2+3*x+2, 9*x^15+5*x^14-3*x^13-3*x^12+5*x^11+3*x^10-2*x^9-8*x^8+2*x^7+4*x^6-5*x^5-2*x^4+8*x^3-2*x^2-x-4]
[7*x^15+2*x^14-6*x^13+x^12+3*x^11+2*x^10-2*x^9-7*x^7-3*x^6+3*x^5-4*x^4+x^3-2*x^2+3*x-4, -6*x^15-2*x^14-6*x^13-7*x^12+9*x^11-2*x^10-8*x^9-7*x^8+5*x^7-8*x^6+3*x^5-8*x^4-8*x^3-7*x^2-x+7]
[-7*x^15-6*x^14-4*x^13+2*x^12+9*x^11+6*x^10-x^9-7*x^8-6*x^7-3*x^6+5*x^5-2*x^4-3*x^3-3*x^2+4, -3*x^15+9*x^14+x^13-6*x^12+8*x^11-x^10+4*x^9+3*x^8+2*x^7+9*x^6+x^5+3*x^4+4*x^3-5*x^2-8*x+5]
[3*x^15-7*x^14+9*x^13+7*x^12+7*x^11+2*x^10-6*x^9+2*x^8+3*x^7+3*x^6-4*x^5-8*x^4-x^3-5*x^2+7*x+9, 8*x^15+8*x^14-7*x^13+7*x^12+x^11-8*x^10-8*x^9+6*x^8-6*x^7+5*x^6+x^5-6*x^4-5*x^2+3*x]
[-5*x^15-6*x^14+8*x^13+6*x^12+5*x^11+6*x^10+9*x^9-7*x^8-2*x^7-7*x^6+5*x^5+4*x^4+9*x^3+7*x^2+2*x+2, -3*x^15+9*x^14+x^13-6*x^12+8*x^11-x^10+4*x^9+3*x^8+2*x^7+9*x^6+x^5+3*x^4+4*x^3-5*x^2-8*x+5]
[9*x^15+9*x^14+9*x^13-7*x^12+x^11+6*x^9+8*x^8-x^7-5*x^6+6*x^5+4*x^4-5*x^3-7*x^2+3*x+1, 8*x^15+8*x^14-7*x^13+7*x^12+x^11-8*x^10-8*x^9+6*x^8-6*x^7+5*x^6+x^5-6*x^4-5*x^2+3*x]
[2*x^15-8*x^14+4*x^13-7*x^12-4*x^11+3*x^10-7*x^9-8*x^8+6*x^7+6*x^6+5*x^5+4*x^4-8*x^3+9*x^2+3*x-4, 9*x^15+5*x^14-3*x^13-3*x^12+5*x^11+3*x^10-2*x^9-8*x^8+2*x^7+4*x^6-5*x^5-2*x^4+8*x^3-2*x^2-x-4]
[5*x^15-7*x^14-x^13-7*x^12-3*x^11+4*x^9+4*x^8+x^7+5*x^6-6*x^5-6*x^4+x^3+3*x^2+x-1, 8*x^15+8*x^14-7*x^13+7*x^12+x^11-8*x^10-8*x^9+6*x^8-6*x^7+5*x^6+x^5-6*x^4-5*x^2+3*x]
[-6*x^15-2*x^14-4*x^13+5*x^12+2*x^11+x^10-x^9+8*x^8-4*x^7-2*x^6-x^5-6*x^4+4*x^3-3*x^2+x-4, 9*x^15+5*x^14-3*x^13-3*x^12+5*x^11+3*x^10-2*x^9-8*x^8+2*x^7+4*x^6-5*x^5-2*x^4+8*x^3-2*x^2-x-4]
```

### 定义核心操作

```cpp
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
```