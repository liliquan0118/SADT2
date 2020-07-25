/*************************************************************************
	> File Name: nss.h
	> Author:
	> Mail:
	> Created Time: 2019年12月29日 星期日 20时45分34秒
 ************************************************************************/

#ifndef _NSS_H
#define _NSS_H

#include "common.h"

#ifdef CONFIG_USE_DER
const static char *LIB_NSS = "lib/libnss_der.so";
#else
const static char *LIB_NSS = "lib/libnss_pem.so";
#endif

extern "C"
int verify_cert_mem(const uint8_t *data_cert, uint32_t size_cert);
extern "C"
int verify_cert_mem_nss(const uint8_t *data_cert, uint32_t size_cert);

#endif  //__GNUTLS_H__


