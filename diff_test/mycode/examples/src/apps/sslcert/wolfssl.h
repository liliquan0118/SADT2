/*************************************************************************
	> File Name: wolfssl.h
	> Author:
	> Mail:
	> Created Time: 2019年12月28日 星期六 01时33分33秒
 ************************************************************************/

#ifndef _WOLFSSL_H
#define _WOLFSSL_H

#include "common.h"

#ifdef CONFIG_USE_DER
const static char *LIB_WOLFSSL = "lib/libwolfssl_der.so";
#else
const static char *LIB_WOLFSSL = "lib/libwolfssl_pem.so";
#endif

extern "C"
int verify_cert_mem(const uint8_t *data_cert, uint32_t size_cert);
extern "C"
int verify_cert_mem_wolfssl(const uint8_t *data_cert, uint32_t size_cert);

#endif  //__GNUTLS_H__
