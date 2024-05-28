/*****************************************************************************
Filename    : main.c
Author      : Terrantsh (tanshanhe@foxmail.com)
Date        : 2018-9-22 18:18:54
Description : 实现了RSA2048加密解密的各项功能，并能够进行最大256位的加密操作
*****************************************************************************/
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "rsa.h"
#include "keys.h"

/*
 * RSA2048 encrypt and decrypt
 * include rsa.c/bignum.c/rsa.h/bignum.h/keys.h
 */
static int RSA2048(void){
    int ret;
    rsa_pk_t pk = {0};
    rsa_sk_t sk = {0};
    uint8_t output[256];

    // message to encrypt
    uint8_t input [256] = { 'h' ,'e','l','l','o'};

    unsigned char msg [256];
    uint32_t outputLen, msg_len;
    uint8_t  inputLen;

    // copy keys.h message about public key and private key to the flash RAM
    pk.bits = KEY_M_BITS;
    memcpy(&pk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m) ],  key_m,  sizeof(key_m ));
    memcpy(&pk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_e) ],  key_e,  sizeof(key_e ));
    sk.bits = KEY_M_BITS;
    memcpy(&sk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m) ],  key_m,  sizeof(key_m ));
    memcpy(&sk.public_exponet  [RSA_MAX_MODULUS_LEN-sizeof(key_e) ],  key_e,  sizeof(key_e ));
    memcpy(&sk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_pe)],  key_pe, sizeof(key_pe));
    memcpy(&sk.prime1          [RSA_MAX_PRIME_LEN - sizeof(key_p1)],  key_p1, sizeof(key_p1));
    memcpy(&sk.prime2          [RSA_MAX_PRIME_LEN - sizeof(key_p2)],  key_p2, sizeof(key_p2));
    memcpy(&sk.prime_exponent1 [RSA_MAX_PRIME_LEN - sizeof(key_e1)],  key_e1, sizeof(key_e1));
    memcpy(&sk.prime_exponent2 [RSA_MAX_PRIME_LEN - sizeof(key_e2)],  key_e2, sizeof(key_e2));
    memcpy(&sk.coefficient     [RSA_MAX_PRIME_LEN - sizeof(key_c) ],  key_c,  sizeof(key_c ));

    inputLen = strlen((const char*)input);
    printf("inputLen (%d)\n", inputLen);
    // public key encrypt
    rsa_public_encrypt(output, &outputLen, input, inputLen, &pk);
    printf("rsa_public_encrypt (%d)\n", outputLen);
    for (uint32_t i = 0; i < outputLen;i++) {
        if (i%10==0) {
            printf("\n");
        }
        printf("0x%02x,", output[i]);
    }
    printf("\n");
    // private key decrypt
    rsa_private_decrypt(msg, &msg_len, output, outputLen, &sk);
    printf("rsa_private_decrypt (%d)\n", outputLen);
    for (uint32_t i = 0; i < msg_len; i++) {
        if (i % 10 == 0) {
            printf("\n");
        }
        printf("0x%02x,", msg[i]);
    }
    printf("\n");
    printf("===================================\n");
    // private key encrypt
    rsa_private_encrypt(output, &outputLen, input, inputLen, &sk);

    printf("rsa_private_encrypt (%d)\n", outputLen);
    for (uint32_t i = 0; i < outputLen; i++) {
        if (i % 10 == 0) {
            printf("\n");
        }
        printf("0x%02x,", output[i]);
    }
    printf("\n");


    // public key decrypted
    rsa_public_decrypt(msg, &msg_len, output, outputLen, &pk);
    printf("rsa_public_decrypt (%d)\n", msg_len);
    for (uint32_t i = 0; i < msg_len; i++) {
        if (i % 10 == 0) {
            printf("\n");
        }
        printf("0x%02x,", msg[i]);
    }
    printf("\n");
    return 0;
}
/* RSA2048 function ended */

int main(int argc, char const *argv[])
{
    clock_t start, finish;
    double  duration;
    start = clock();    // init start time
    RSA2048();
    finish = clock();   // print end time
    duration = (double)(finish - start) / CLOCKS_PER_SEC;   // print encrypt and decrypt time
    printf( "%f seconds\n", duration );
    return 0;
}
 