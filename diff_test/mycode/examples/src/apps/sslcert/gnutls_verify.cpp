/*************************************************************************
	> File Name: gnutls_verify.cpp
	> Author:
	> Mail:
	> Created Time: 2020年01月15日 星期三 21时04分01秒
 ************************************************************************/

#include <iostream>
using namespace std;



#include "gnutls.h"

#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
// //加载证书文件，返回gnutls_datum_t
static gnutls_datum_t load_cert(const char *cert_file)
{
    gnutls_datum_t data;
    FILE * pFile;
    long lSize;
    unsigned char * buffer;
    size_t result;
    data.data=NULL;
    /* 若要一个byte不漏地读入整个文件，只能采用二进制方式打开 */
    pFile = fopen (cert_file, "rb" );
    if (pFile==NULL)
    {
        fputs ("File error",stderr);
        printf("%s",cert_file);
        return data;
    }

    /* 获取文件大小 */
    fseek (pFile , 0 , SEEK_END);
    lSize = ftell (pFile);
    rewind (pFile);

    /* 分配内存存储整个文件 */
    buffer = (unsigned char*) malloc (sizeof(unsigned char)*lSize+1);

    if (buffer == NULL)
    {
        fputs ("Memory error",stderr);
        exit(-1);
    }
    buffer[lSize]='\0';
    /* 将文件拷贝到buffer中 */
    result = fread (buffer,1,lSize,pFile);
    if (result != lSize)
    {
        fputs ("Reading error",stderr);
        exit(-1);
    }

    data.data = buffer;
    data.size = lSize;
    if (!data.data) {
        fprintf(stderr, "Cannot open file: %s\n", cert_file);
    }
    fclose (pFile);
    return data;
}

int verify_cert_mem(const uint8_t *data_cert, uint32_t size_cert)
{
    int ret;
    unsigned int num=2;
    gnutls_x509_crt_t cert;
    gnutls_x509_crt_t* ca;
    ret = gnutls_x509_crt_init(&cert);
    // ca =(gnutls_x509_crt_t *)malloc(sizeof(gnutls_x509_crt_t) *num);
    if (ret < 0)
    {
        // free(ca);
        gnutls_x509_crt_deinit(cert);
        return -1;
    }
    // load_cert_chain_from_mem( data_cert, size_cert);
    //加载被验证的证书
    // gnutls_datum_t data=load_cert("certficate.pem");

    unsigned char *buffer = (unsigned char*) malloc (sizeof(unsigned char)*size_cert+1);
    memcpy(buffer,data_cert,size_cert);
    buffer[size_cert]='\0';
    gnutls_datum_t data ,data2;
    data.data = buffer;
    data.size = size_cert;
    //cert存放解析的证书
    ret = gnutls_x509_crt_import(cert, &data, GNUTLS_X509_FMT_PEM);
    if (ret < 0) {
        // fprintf(stderr, "Cannot import certificate in : %s\n", gnutls_strerror(ret));
        // free(ca);
        gnutls_x509_crt_deinit(cert);
        free(buffer);
        return -1;
    }

    free(buffer);
    // // //加载证书链
    // data2=load_cert("ca.pem");
    data2=load_cert("/home/quanlili/cert-chain10/1.pem");
    if(!data2.data)
    {
        // free(ca);
        return -1;
    }

    ca =(gnutls_x509_crt_t *)malloc(sizeof(gnutls_x509_crt_t) *num);
    ret = gnutls_x509_crt_list_import(ca,&num, &data2, GNUTLS_X509_FMT_PEM,0);
    // free(data2.data);
    // gnutls_free(&data);
    if (ret < 0) {
        free(ca);
        gnutls_x509_crt_deinit(cert);
        fprintf(stderr, "Cannot import cacertificate in: %s\n", gnutls_strerror(ret));
        free(data2.data);
        return -1;
    }
    unsigned int verify=0;
    // //验证，cert: is the certificate to be verified，ca is one certificate that is considered to be trusted one,2 holds the number of CA certificate，verify will hold the certificate verification output.
    gnutls_x509_crt_verify(cert,ca,2,GNUTLS_VERIFY_DISABLE_CRL_CHECKS,&verify);
    gnutls_datum_t txt;
    gnutls_certificate_verification_status_print(verify,GNUTLS_CRT_X509,&txt, 0);
    // printf("状态码: %d\n描述:%s\n",verify,txt.data);
    DBG_S("gnutls:%d:%s\n", verify,txt.data);
    gnutls_free(txt.data);
    // free(ca);
    for(int i=num-1;i>=0;i--)
    gnutls_x509_crt_deinit(ca[i]);
    gnutls_x509_crt_deinit(cert);
    free(data2.data);
    free(ca);
    return verify;
}

int main(int argc, char **argv)
{
   char *file=argv[1];

    FILE * pFile;
    int lSize;
    pFile = fopen (file, "rb" );
    if (pFile==NULL)
    {
        fputs ("File error",stderr);
        printf("%s",file);
    }

    /* 获取文件大小 */
    fseek (pFile , 0 , SEEK_END);
    lSize = ftell (pFile);
    rewind (pFile);

    /* 分配内存存储整个文件 */
   unsigned char* buffer = (unsigned char*) malloc (sizeof(unsigned char)*lSize+1);

    if (buffer == NULL)
    {
        fputs ("Memory error",stderr);
        exit(-1);
    }
    buffer[lSize]='\0';
    /* 将文件拷贝到buffer中 */
   int result = fread (buffer,1,lSize,pFile);
    if (result != lSize)
    {
        fputs ("Reading error",stderr);
        exit(-1);
    }
    int ret=verify_cert_mem(buffer,lSize);
    printf("%d\n",ret);
    return 0;
}
