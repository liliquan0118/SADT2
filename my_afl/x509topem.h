//
// Created by quanlili on 19-9-17.
//

#ifndef MY_OPENSSL_X509TOPEM_H
#define MY_OPENSSL_X509TOPEM_H
#include "alloc-inl.h"
#include "tlv.h"

int PEM_generate_from_X509(char *key_file, i2d_of_void *i2d, d2i_of_void *d2i, BIO *bp, X509 *x);
int X509_2_PEM(char *key_file, BIO *bp, X509 *x);
#endif //MY_OPENSSL_X509TOPEM_H
