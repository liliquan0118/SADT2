/*************************************************************************
	> File Name: mbedtls.h
	> Author:
	> Mail:
	> Created Time: 2019年12月27日 星期五 21时54分43秒
 ************************************************************************/

#ifndef _MBEDTLS_H
#define _MBEDTLS_H

#include "common.h"

#ifdef CONFIG_USE_DER
const static char *LIB_MBEDTLS = "lib/libmbedtls_der.so";
#else
const static char *LIB_MBEDTLS = "lib/libmbedtls_pem.so";
#endif
extern "C"
int verify_cert_mem(const uint8_t *data_cert, uint32_t size_cert);
extern "C"
int verify_cert_mem_mbedtls(const uint8_t *data_cert, uint32_t size_cert);

#endif  //__MBEDTLS_H__
