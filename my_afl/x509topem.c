//
// Created by quanlili on 19-9-17.
//
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
///#include <wolfssl/options.h>
//#include <wolfssl/ssl.h>
//#include <wolfssl/wolfcrypt/error-crypt.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/md2.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/mdc2.h>
//#include <gmpxx.h>
#include "/home/quanlili/my_openssl/crypto/x509/x509_lcl.h"
#include "/home/quanlili/my_openssl/crypto/include/internal/x509_int.h"
#include "/home/quanlili/my_openssl/crypto/include/internal/asn1_int.h"
#include "/home/quanlili/my_openssl/include/openssl/obj_mac.h"
#include "x509topem.h"
/* #include "alloc-inl.h" */
/* #include "tlv.h" */
#define EXTNAME_LEN 50
#define obey 50
#define violate 50
#define MAXLEN 10000000
typedef unsigned int u32;
int X509_2_PEM(char *key_file, BIO *bp, X509 *x){
    return  PEM_generate_from_X509(key_file,(i2d_of_void *)i2d_X509_AUX,(d2i_of_void *)d2i_X509_AUX,bp,x);
}
int PEM_generate_from_X509(char *key_file, i2d_of_void *i2d, d2i_of_void *d2i, BIO *bp, X509 *x){
if(x==NULL)
  {
  printf("x内容为空！\n");
  }

    int dsize = 0, len = 0, ret = 0;
    unsigned char *p,*p1,  *data = NULL;
    const char *name = "CERTIFICATE";
    char buf[PEM_BUFSIZE];
    unsigned char *data_buf=ck_alloc(MAXLEN*sizeof(unsigned char));
    unsigned char *signature=ck_alloc(MAXLEN*sizeof(unsigned char));
    /* unsigned char *data_buf=OPENSSL_malloc(MAXLEN*sizeof(unsigned char)); */
    /* unsigned char *signature=OPENSSL_malloc(MAXLEN*sizeof(unsigned char)); */
    u32 sig_len;
    BIO *bio_err=NULL;
    bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);

    if ((dsize = i2d(x, NULL)) < 0) {
        PEMerr(PEM_F_PEM_ASN1_WRITE_BIO, ERR_R_ASN1_LIB);
        dsize = 0;
        goto err;
    }
    /* dsize + 8 bytes are needed
     * actually it needs the cipher block size extra...
     * */
    /* data = (unsigned char*)ck_alloc((unsigned int)dsize + 800); */
    data = (unsigned char*)OPENSSL_malloc((unsigned int)dsize + 800);
    if (NULL == data){
        PEMerr(PEM_F_PEM_ASN1_WRITE_BIO, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    p = data;
    //i2d将内部结构x509转换成DER编码格式，p指向生成的DER字符串结束位置
    len = i2d(x, &p);
    /* Get the der after muatation, resign the digest, and update the der. */
    p1 = data;
/* BiTree T = NULL; */
/* unsigned char *p2 = p1; */
/* tlv(&T, &p2,p1);//parse tlv structure into tree */
    /* //将x509作为返回值返回，p重置到p+len的位置上 */
/* BiTree t_signature=T->lchild->rchild->rchaild; */
/* int loc_sig=t_signature->t;//signature字段的t的位置 */
/* int totallen=len; */
/* update(&T, loc_sig,signature , *len1, &p1, &totallen); */
/* FILE*f=fopen("pder.txt","w"); */
/* for(int i=0;i<len;i++) */
/* fprintf(f,"%02x ",p1[i]); */
/* fclose(f); */
    /* printf("\n"); */
    /* printf("%d\n",len); */
X509 *x2;
    x2 = d2i(NULL,&p1,len);
     /* d2i_X509_AUX(&x2,&p1,len); */
if(x2==NULL)
{
printf("x2内容为空！\n");
/* exit(1); */
}
    RSA *private_key = NULL;
    DSA *dsa=NULL;
    EC_KEY *ec_key = NULL;
    FILE *fp;
    if (NULL==(fp = fopen(key_file,"r+"))){
        perror("Fail to open file!");
        exit(1);
    }
    /*读取该证书中使用的签名算法,并读取用来签名该证书的私钥*/
    //	const char *alg2=x->sig_alg.algorithm->ln;
    /* const char *alg1=x2->sig_alg.algorithm->sn; */
    const char *alg1=x->sig_alg.algorithm->sn;
    if(strstr(alg1,"RSA"))
    {	if(NULL==(private_key=PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL)))
        {
            printf("error1\n");
            ERR_print_errors_fp(stdout);
            exit(1);
        }
    }
    else if(strstr(alg1,"ecdsa"))
    {	if(NULL==(ec_key = PEM_read_ECPrivateKey(fp,NULL,NULL,NULL)))
        {
            printf("error2\n");
            ERR_print_errors_fp(stdout);
            exit(1);
        }
    }
    else if(strstr(alg1,"dsa"))
    {	if(NULL==(dsa=PEM_read_DSAPrivateKey(fp,NULL,NULL,NULL)))
        {
            printf("error3\n");
            ERR_print_errors_fp(stdout);
            exit(1);
        }
    }
    else {
        printf("\n无法识别签名算法:%s！\n",alg1);
        exit(1);
    }

    fclose(fp);
    /* Conduct SHA256 hash for the der contents of x509->cert_info */
int signa;
        SHA256(x->cert_info.enc.enc, x->cert_info.enc.len,data_buf);
        // Sign the SHA256 digest using the private key
        signa = RSA_sign(NID_sha256,(unsigned char *)data_buf,32,(unsigned char *)signature,&sig_len,private_key);

BiTree T = NULL;
unsigned char *p2 = p1;
tlv(&T, &p2,p1);//parse tlv structure into tree
    //将x509作为返回值返回，p重置到p+len的位置上
BiTree t_signature=T->lchild->rchild->rchild;
int loc_sig=t_signature->t;//signature字段的t的位置
long totallen=len;
update(&T, loc_sig,signature , sig_len, &p1, &totallen);

FILE*f=fopen("pder.txt","w");
for(int i=0;i<len;i++)
fprintf(f,"%02x ",p1[i]);
fclose(f);

int sign;
    if(strcmp(alg1,"RSA-SHA256")==0)
    {
        SHA256(x2->cert_info.enc.enc, x2->cert_info.enc.len,data_buf);
        // Sign the SHA256 digest using the private key
        sign = RSA_sign(NID_sha256,(unsigned char *)data_buf,32,(unsigned char *)signature,&sig_len,private_key);
    }
    else if(strcmp(alg1,"RSA-SHA224")==0)
    {
        SHA224(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        // Sign the SHA224 digest using the private key
        sign = RSA_sign(NID_sha224,(unsigned char *)data_buf,28,(unsigned char  *)signature,&sig_len,private_key);

    }
    else if(strcmp(alg1,"RSA-SHA1")==0)
    {
        SHA1(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = RSA_sign(NID_sha1,(unsigned char *)data_buf,20,(unsigned char*)signature,&sig_len,private_key);
    }
    else if(strcmp(alg1,"RSA-SHA384")==0)
    {
        SHA384(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = RSA_sign(NID_sha384,(unsigned char  *)data_buf,48,(unsigned char  *)signature,&sig_len,private_key);
    }
    else if(strcmp(alg1,"RSA-SHA512")==0)
    {
        SHA512(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = RSA_sign(NID_sha512,(unsigned char  *)data_buf,64,(unsigned char  *)signature,&sig_len,private_key);

    }
    else if(strcmp(alg1,"RSA-MD4")==0)
    {
        MD4(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = RSA_sign(NID_md4,(unsigned char  *)data_buf,16,(unsigned char  *)signature,&sig_len,private_key);
    }
    else if(strcmp(alg1,"RSA-MD5")==0)
    {
        MD5(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = RSA_sign(NID_md5,(unsigned char  *)data_buf,16,(unsigned char  *)signature,&sig_len,private_key);
    }
//	else if(strcmp(alg1,"RSA-MDC2")==0)
//	{
//		MDC2(x->cert_info.enc.enc,x->cert_info.enc.len,data_buf);
///		sign = RSA_sign(NID_mdc2,(u8 *)data_buf,16,(u8 *)signature,&sig_len,private_key);
//	}
    else if(strcmp(alg1,"dsa_with_SHA256")==0)
    {
        SHA256(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = DSA_sign(NID_sha256,(unsigned char  *)data_buf,32,(unsigned char  *)signature,&sig_len,dsa);
    }
    else if(strcmp(alg1,"dsa_with_SHA224")==0)
    {
        SHA224(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = DSA_sign(NID_sha224,(unsigned char  *)data_buf,28,(unsigned char  *)signature,&sig_len,dsa);
    }
    else if(strcmp(alg1,"dsa_with_SHA1")==0)
    {
        SHA1(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = DSA_sign(NID_sha1,(unsigned char  *)data_buf,20,(unsigned char  *)signature,&sig_len,dsa);
    }
    else if(strcmp(alg1,"dsa_with_SHA384")==0)
    {
        SHA384(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = DSA_sign(NID_sha384,(unsigned char  *)data_buf,48,(unsigned char  *)signature,&sig_len,dsa);
    }
    else if(strcmp(alg1,"dsa_with_SHA512")==0)
    {
        SHA512(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = DSA_sign(NID_sha512,(unsigned char  *)data_buf,64,(unsigned char  *)signature,&sig_len,dsa);

    }
    else if(strcmp(alg1,"dsa_with_MD4")==0)
    {
        MD4(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = DSA_sign(NID_md4,(unsigned char  *)data_buf,16,(unsigned char  *)signature,&sig_len,dsa);
    }
    else if(strcmp(alg1,"dsa_with_MD5")==0)
    {
        MD5(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = DSA_sign(NID_md5,(unsigned char  *)data_buf,16,(unsigned char  *)signature,&sig_len,dsa);
    }
    else if(strcmp(alg1,"ecdsa-with-SHA256")==0)
    {
        SHA256(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = ECDSA_sign(NID_sha256,(unsigned char  *)data_buf,32,(unsigned char  *)signature,&sig_len,ec_key);
    }
    else if(strcmp(alg1,"ecdsa-with-SHA224")==0)
    {
        SHA224(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = ECDSA_sign(NID_sha224,(unsigned char  *)data_buf,28,(unsigned char  *)signature,&sig_len,ec_key);

    }
    else if(strcmp(alg1,"ecdsa-with-SHA1")==0)
    {
        SHA1(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = ECDSA_sign(NID_sha1,(unsigned char  *)data_buf,20,(unsigned char  *)signature,&sig_len,ec_key);
    }
    else if(strcmp(alg1,"ecdsa-with-SHA384")==0)
    {
        SHA384(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = ECDSA_sign(NID_sha384,(unsigned char  *)data_buf,48,(unsigned char  *)signature,&sig_len,ec_key);
    }
    else if(strcmp(alg1,"ecdsa-with-SHA512")==0)
    {
        SHA512(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = ECDSA_sign(NID_sha512,(unsigned char  *)data_buf,64,(unsigned char  *)signature,&sig_len,ec_key);

    }
    else if(strcmp(alg1,"ecdsa-with-MD4")==0)
    {
        MD4(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = ECDSA_sign(NID_md4,(unsigned char  *)data_buf,16,(unsigned char  *)signature,&sig_len,ec_key);
    }
    else if(strcmp(alg1,"ecdsa-with-MD5")==0)
    {
        MD5(x2->cert_info.enc.enc,x2->cert_info.enc.len,data_buf);
        sign = ECDSA_sign(NID_md5,(unsigned char  *)data_buf,16,(unsigned char  *)signature,&sig_len,ec_key);


    }
    else{
        printf("无法识别%s算法！\n",alg1);
        exit(1);
    }
    unsigned char  *sig;
    if(sign != 1){
        perror("Fail to sign the digest!");
        RSA_free(private_key);
        return 0;
    }else{
        //printf("Sign successfully!\n");
        /* Merge the der of tbscertificate,sig_alg with the newly generated signature
         * to form a new certificate, stored in data.
         * */
        unsigned char*sd=x2->signature.data;
        OPENSSL_free(sd);
        //sig = (unsigned char  *)OPENSSL_malloc(sig_len);
        sig = (unsigned char  *)OPENSSL_malloc(sig_len);
        memmove(sig,signature,sig_len);
        x2->signature.data = sig;
        x2->signature.length = sig_len;
    }
    if(!PEM_write_bio_X509(bp,x2))
    {
        BIO_printf(bio_err,"unable to write certificate\n");
        ERR_print_errors(bio_err);
    }
        //printf("x509 DER convert to PEM successfully...\n");

    err:
    ck_free(data_buf);
    ck_free(signature);
    /* OPENSSL_free(data_buf); */
    /* OPENSSL_free(signature); */
    X509_free(x2);
    RSA_free(private_key);
    DSA_free(dsa);
    OPENSSL_cleanse(buf, PEM_BUFSIZE);
    /* ck_free(data); */
    OPENSSL_free(data);
    return 0;
}
