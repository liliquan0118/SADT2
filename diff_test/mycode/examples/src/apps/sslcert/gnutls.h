#ifndef __GNUTLS_H__
#define __GNUTLS_H__

#include "common.h"


#ifdef CONFIG_USE_DER
const static char *LIB_GNUTLS = "lib/libgnutls_der.so";
#else
const static char *LIB_GNUTLS = "lib/libgnutls_pem.so";
#endif

extern "C"
int verify_cert_mem(const uint8_t *data_cert, uint32_t size_cert);
extern "C"
int verify_cert_mem_gnutls(const uint8_t *data_cert, uint32_t size_cert);

#endif  //__GNUTLS_H__
