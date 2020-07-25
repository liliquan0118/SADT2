/*************************************************************************
	> File Name: wolfssl.cpp
	> Author:
	> Mail:
	> Created Time: 2019年12月28日 星期六 01时21分33秒
 ************************************************************************/

#include "wolfssl.h"
#include <assert.h>

// #include <openssl/ssl.h>
// #include <openssl/err.h>
// #include <openssl/x509.h>
// #include <openssl/x509_vfy.h>
// #include <openssl/bio.h>
// // #include <openssl/crypto.h>
// #include <openssl/pem.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

extern "C"
LIB_EXPORT
int verify_cert_mem(const uint8_t *data_cert, uint32_t size_cert)
{

    // remove("leaf.pem");
    // FILE *fp = NULL;
    // fp = fopen("leaf.pem", "w+");
    // fputs((char *)data_cert, fp);
    // fclose(fp);
    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    cm = wolfSSL_CertManagerNew();//new a certmanager to verify certificate
    if(cm == NULL) {
        printf("error creating new cert manager\n");
    }
    ret = wolfSSL_CertManagerLoadCA(cm,"../../../../../cert-chain10/1.pem", NULL);
    if (ret != SSL_SUCCESS) {
        printf ("error loading CA certs into cert manager\n");
    }
    // ret = wolfSSL_CertManagerVerify(cm, "leaf.pem",SSL_FILETYPE_PEM);
    ret = wolfSSL_CertManagerVerifyBuffer(cm, data_cert,size_cert,SSL_FILETYPE_PEM);
    // ret = wolfSSL_CertManagerVerifyBuffer(cm, data_cert,size_cert,SSL_FILETYPE_ASN1);
    wolfSSL_CertManagerFree(cm);
    if (ret != SSL_SUCCESS) {
       // int a=ret;
      // char buffer[80];
       // wolfSSL_ERR_error_string(ret, buffer);
        // printf("err = %d, %s\n",ret, buffer);
        // wolfSSL_ERR_reason_error_string(-144);
        // printf("wolfSSL_CertManagerVerify() failed (%d): %s\n",ret, wolfSSL_ERR_reason_error_string(ret));
        return ret;
    }
    else
    {
        // printf("Verification Successful!\n");
        return 0;
    }

}

extern "C"
LIB_EXPORT
int verify_cert_mem_wolfssl(const uint8_t *data_cert, uint32_t size_cert)
{
    return verify_cert_mem(data_cert, size_cert);
}




