/*************************************************************************
	> File Name: nss.cpp
	> Author:
	> Mail:
	> Created Time: 2019年12月29日 星期日 19时53分03秒
 ************************************************************************/


#include <assert.h>
#include "nss.h"
#include <nss/secport.h>
#include <nspr/prerror.h>
#include <nss/nss.h>
#include <nss/cert.h>
#include <nss/nssb64.h>
#include <nss/secerr.h>


extern "C"
LIB_EXPORT
int verify_cert_mem(const uint8_t *data_cert, uint32_t size_cert)
{

    // FILE *fp = NULL;
    // fp = fopen("leaf.pem", "w+");
    // // fprintf( fp,(char *)data_cert);
    // fputs((char *)data_cert,fp);
    // fclose(fp);
    CERTCertificate *cert2;
	int r=NSS_Init("../../../../../cert-chain10/nssdb");
   // int r=NSS_InitReadWrite(ca_file);
	if (r != SECSuccess)
		printf("init nss failure\n");
	// char *buffer = (char*) malloc (sizeof(char)*size_cert);
    // memset(buffer,0,size_cert);
    // memcpy(buffer,data_cert,size_cert);
    CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	if (handle == NULL)
		printf("problem getting certdb handle\n");
	// cert2 =nss_load_cert("leaf.pem") ;
	// cert2= CERT_DecodeCertFromPackage(buffer,(int)size_cert);
	cert2= CERT_DecodeCertFromPackage((char *)data_cert,(int)size_cert);
    if(!cert2)
    {
    // free(buffer);
    return -1;
    }
	int state_code=-1;
    int rv=CERT_VerifyCertNow(handle,cert2,PR_TRUE,certUsageSSLServer,NULL);
	// int rv=CERT_VerifyCertNow(handle,cert2,PR_TRUE,,NULL);
    if (rv != SECSuccess) {
        rv = PORT_GetError();
        // printf("状态码:%d\n描述:%s\n",rv,PORT_ErrorToString(rv));
        state_code=rv;
    }
    else
    {
        // printf("状态码:%d\n描述:OK\n",rv);
        state_code=rv;
    }
	CERT_DestroyCertificate(cert2);
	int shut=NSS_Shutdown();
	if (shut != SECSuccess)
		printf("shut nss failure\n");
    // free(buffer);
    return state_code;
}

extern "C"
LIB_EXPORT
int verify_cert_mem_nss(const uint8_t *data_cert, uint32_t size_cert)
{
    return verify_cert_mem(data_cert, size_cert);
}






