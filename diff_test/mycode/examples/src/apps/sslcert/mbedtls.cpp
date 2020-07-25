/*************************************************************************
	> File Name: mbedtls.cpp
	> Author:
	> Mail:
	> Created Time: 2019年12月27日 星期五 21时50分14秒
 ************************************************************************/
#include "mbedtls.h"

#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <string.h>
#include<mbedtls/ssl.h>
#include<mbedtls/certs.h>
#include<mbedtls/error.h>

extern "C"
LIB_EXPORT
int verify_cert_mem(const uint8_t *data_cert, uint32_t size_cert)
{

    remove("leaf.pem");
    FILE *fp = NULL;
    fp = fopen("leaf.pem", "w+");
    fputs((char *)data_cert, fp);
    fclose(fp);
    int ret;
	uint32_t flags;
	mbedtls_x509_crt cacert;
	mbedtls_x509_crt cert;
	mbedtls_x509_crt_init( &cacert );
	mbedtls_x509_crt_init( &cert );
    // load_cert_chain_from_mem( data_cert, size_cert);
    //Load the trusted CA
	ret = mbedtls_x509_crt_parse_file( &cacert, "../../../../../cert-chain10/1.pem" );
	if( ret != 0 )
	{
		//printf( " failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\nfile:%s\n", -ret,ca_cert_file);
		// exit(1);
        mbedtls_x509_crt_free(&cacert);
        mbedtls_x509_crt_free(&cert);
        // return ret;
        return -1;
	}
	//Load to be verified certificate
    // ret = mbedtls_x509_crt_parse_der( &cert,data_cert,size_cert );
    ret = mbedtls_x509_crt_parse_file( &cert, "leaf.pem" );
	if( ret != 0 )
	{
		//	printf( " failed\n  !  mbedtls_x509_crt_parse_file returned -0x%X\nfile:%s\n", -ret,cert_file);
		//printf("状态码:%d\n",ret);
		//	exit(1);
		char tmp[100];
		mbedtls_strerror(ret, tmp, 100);
		//printf("描述:%s\n",tmp);
        mbedtls_x509_crt_free(&cacert);
        mbedtls_x509_crt_free(&cert);
		// return ret;
        return -1;
    }
	//verify
	int state_code=0;
	ret=mbedtls_x509_crt_verify(&cert, &cacert, NULL, NULL, &flags, NULL,NULL);
	if( ret != 0 )
	{
		if( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED )
		{
			char vrfy_buf[512];

			mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
            // printf( "状态码:%d\n描述:%s\n",flags,vrfy_buf );
			state_code=flags;
		}
		else
		{
			printf( " failed\n  !  mbedtls_x509_crt_verify returned %d\n\n", ret );
            mbedtls_x509_crt_free(&cert);
            mbedtls_x509_crt_free(&cacert);
		    return ret;
		}

	}
	else
	{
		//printf("状态码:%d\n描述:OK\n",ret);
		state_code=0;
	}
	mbedtls_x509_crt_free(&cacert);
	mbedtls_x509_crt_free(&cert);
	return state_code;
}

extern "C"
LIB_EXPORT
int verify_cert_mem_mbedtls(const uint8_t *data_cert, uint32_t size_cert)
{
    return verify_cert_mem(data_cert, size_cert);
}


