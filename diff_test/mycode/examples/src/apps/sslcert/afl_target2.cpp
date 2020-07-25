#include <assert.h>
//#include <pthread.h>
#include <stdint.h>

#include "common.h"
#include "func.h"

// include generic structures for diff-based fuzzing
#include "diff_afl.h"



#ifndef CONFIG_USE_OPENSSL
// just in case openssl is not in the build
int ret_openssl = FAILURE_INTERNAL;
#endif

#define INCLUDE(name) \
static fp_t verify_cert_ ##name = NULL; \
static void *h_ ##name = NULL; \
int ret_ ##name = FAILURE_INTERNAL; \
uint8_t * cert_chain_ ##name = NULL; \
size_t cert_chain_sz_ ##name;

uint8_t * cert_chain_pem_init = NULL;
uint8_t * cert_chain_pem = NULL;
size_t cert_chain_sz_pem;

#ifdef CONFIG_USE_OPENSSL
#include "openssl.h"
INCLUDE(openssl)
#endif

#ifdef CONFIG_USE_LIBRESSL
#include "libressl.h"
INCLUDE(libressl)
#endif

/* #ifdef CONFIG_USE_BORINGSSL */
// #include "boringssl.h"
// INCLUDE(boringssl)
// #endif

#ifdef CONFIG_USE_WOLFSSL
#include "wolfssl.h"
INCLUDE(wolfssl)
#endif

#ifdef CONFIG_USE_MBEDTLS
#include "mbedtls.h"
INCLUDE(mbedtls)
#endif

#ifdef CONFIG_USE_GNUTLS
#include "gnutls.h"
INCLUDE(gnutls)
#endif
#ifdef CONFIG_USE_NSS
#include "nss.h"
INCLUDE(nss)
#endif



#define INIT_LIB(name, NAME) \
  if (!verify_cert_ ##name) { \
    verify_cert_ ##name = \
      (fp_t)get_interface_fn(h_ ##name, LIB_ ##NAME, FN_VERIFY_CERT); \
    if (!verify_cert_ ##name) \
      DBG("ERROR resolving function from: %s\n", LIB_ ##NAME); \
  } \
  assert(verify_cert_ ##name != NULL); \
  total_libs++;

#define INIT_CERTS_DER(name) \
  cert_chain_sz_ ##name = cert_chain_sz_openssl; \
  cert_chain_ ##name = (uint8_t *)cert_chain_openssl;
#define INIT_CERTS_PEM(name) \
  cert_chain_sz_ ##name = cert_chain_sz_pem; \
  cert_chain_ ##name = cert_chain_pem;

#define FREE_LIB_CERTS(name) \
  FREE_PTR(cert_chain_ ##name)

#define VERIFY_ONE(name) \
  ret_ ##name = verify_cert_ ##name(cert_chain_ ##name, \
                                    cert_chain_sz_ ##name);


struct GlobalInitializer {
  GlobalInitializer() {

#ifdef CONFIG_USE_OPENSSL
    INIT_LIB(openssl, OPENSSL)
#endif
#ifdef CONFIG_USE_LIBRESSL
    INIT_LIB(libressl, LIBRESSL)
#endif
// #ifdef CONFIG_USE_BORINGSSL
    // INIT_LIB(boringssl, BORINGSSL)
// #endif
#ifdef CONFIG_USE_WOLFSSL
    INIT_LIB(wolfssl, WOLFSSL)
#endif
#ifdef CONFIG_USE_MBEDTLS
    INIT_LIB(mbedtls, MBEDTLS)
#endif
#ifdef CONFIG_USE_GNUTLS
    INIT_LIB(gnutls, GNUTLS)
#endif
#ifdef CONFIG_USE_NSS
    INIT_LIB(nss, NSS)
#endif


    // initialize all diff-based structures
    // diff_init();
  }

    ~GlobalInitializer() { }
};

static GlobalInitializer g_initializer;

// extern "C" int LLVMFuzzerTestOneInput(const uint8_t *cert_chain_openssl,
                                      // size_t cert_chain_sz_openssl) {
int main(int argc, char *argv[])
{
    uint8_t *cert_chain_openssl = NULL;
    size_t cert_chain_sz_openssl;
    if (argc != 2) {
        printf("usage: %s server_cert\n", argv[0]);
        exit(EXIT_SUCCESS);
    }


    if (!(cert_chain_sz_openssl = read_file(argv[1], &cert_chain_openssl))) {
      printf("ERROR reading file: %s\n", argv[1]);
      if (cert_chain_openssl) {
        free(cert_chain_openssl);
        cert_chain_openssl = NULL;
      }
      exit(EXIT_FAILURE);
    }

  //
  // OpenSSL will dump three files:
  // ca_chain.pem
  // leaf_cert.pem
  // full_pem_chain.pem
  //
  // We will always verify the leaf_cert against the ca_chain.
  //
  EXERCISE(openssl)

  INIT_CERTS_DER(gnutls)
  EXERCISE(gnutls)
  INIT_CERTS_DER(mbedtls)
  EXERCISE(mbedtls)
  INIT_CERTS_DER(nss)
  EXERCISE(nss)
  INIT_CERTS_DER(wolfssl)
  EXERCISE(wolfssl)
  INIT_CERTS_DER(libressl)
  EXERCISE(libressl)
  FILE *file = NULL;
  file = fopen("verify_result.csv", "a");
  if (NULL == file) {
      printf("无法打开文件\n");
  }
  // printf("%d ", ret_openssl); \
// fprintf(file,"%s,%d,%d,%d,%d,%d\n",argv[1],ret_ ##openssl,ret_ ##gnutls,ret_ ##mbedtls,ret_ ##nss,ret_ ##wolfssl,ret_ ##libressl)
fprintf(file,"%s,%d,%d,%d,%d,%d,%d\n",argv[1],ret_openssl,ret_gnutls,ret_mbedtls,ret_nss,ret_wolfssl,ret_libressl);
  FREE_LIB_CERTS(pem_init)
  if (cert_chain_openssl) {
    free(cert_chain_openssl);
    cert_chain_openssl = NULL;
  }
  return 0;
}
