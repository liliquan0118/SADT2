
#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <termios.h>
#include <dlfcn.h>
#include <sched.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
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
//#include "../crypto/x509/x509_lcl.h"
#include "/home/quanlili/my_openssl/crypto/include/internal/x509_int.h"
#include "/home/quanlili/my_openssl/crypto/include/internal/asn1_int.h"
#include "tlv.h"
/* #include "locate.h" */
/* #include "x509topem.h" */
#include"x2pem.h"
#include "locate.h"
int main(){

s32 fd;
    fd = open("/home/quanlili/afl_test/output/fuzzer2/queue/id:000020,src:000001,op:havoc,rep:128,+cov", O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", "id:000020");
u8 *orig_in,in_buf;
    orig_in = in_buf = mmap(0, 100, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (orig_in == MAP_FAILED) PFATAL("Unable to mmap '%s'", "id:000020");
    close(fd);
    /* X509 *x509 = NULL; */
    /* BIO *bio_err = NULL; */
    /* BIO *out = NULL; */
    /* BIO *cert; */
    /* char *certFile="/home/quanlili/afl_test/openssl_output/queue/id:000020,src:000001,op:havoc,rep:128,+cov"; */
    /* if (bio_err == NULL) */
        /* bio_err = BIO_new_fp(stderr, BIO_NOCLOSE); */
    /* if ((cert = BIO_new(BIO_s_file())) == NULL) { */
        /* ERR_print_errors(bio_err); */
    /* } */
    /* if (BIO_read_filename(cert, certFile) <= 0) { */
        /* BIO_printf(bio_err, "Error opening %s %s\n", "Certificate", certFile); */
        /* ERR_print_errors(bio_err); */
    /* } */
/* //读取BIO* cert所绑定的PEM文件，内容写入x509数据结构中 */
    /* x509 = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL); */
    /* if (x509 == NULL) { */
        /* BIO_printf(bio_err, "unable to load certificate\n"); */
        /* ERR_print_errors(bio_err); */
        /* return 0; */
    /* } */
    /*  */
 /* out = BIO_new(BIO_s_file()); */
              /* if (out == NULL) { */
                /* ERR_print_errors(bio_err); */
               /* } */

            /* if (BIO_write_filename(out, "test.pem") <= 0) { */
                   /* perror("test"); */
               /* } */
/* */
/* long len2 =x509->cert_info.enc.len; */
    /* unsigned char *p=x509->cert_info.enc.enc; */
 /* //x509->cert_info.enc.modified = 1; */
 /* BiTree T=NULL; */
/* unsigned char *der=p; */

	/* tlv(&T, &p, der); */
	/* //out_buf is modified content */
	/* char *private_key_file = "/home/quanlili/afl_test/cert-chain10/powerca.key.pem"; */
    /* //x509->cert_info.enc.enc=der; */
    /* //x509->cert_info.enc.len=orig_enc_len; */
    /* [> int dsize = i2d_X509_AUX(x509, NULL); <] */
    /* [> unsigned char*  data = (unsigned char*)ck_alloc(dsize + 800); <] */
    /* [> unsigned char*p2=data; <] */
   /* [> int  len = i2d_X509_AUX(x509, &p2); <] */
       /* [> [> Get the der after muatation, resign the digest, and update the der. <] <] */
       /* [> p2 = data; <] */
   /* [> FILE*f=fopen("der.txt","w"); <] */
   /* [> for(int i=0;i<len;i++) <] */
   /* [> fprintf(f,"%02x ",p2[i]); <] */
   /* [> fprintf(f,"\n\n"); <] */
   /* [> fclose(f); <] */

	/* //	queue_cur->len=len; */
   /* unsigned char out_buf[]={0x0, 0x70, 0x1, 0xb9, 0xe, 0x83, 0x99, 0xec, 0x44, 0xab, 0x49, 0x3d, 0x41, 0x6, 0x9e, 0xc0, 0xd6}; */
   /* [> unsigned char out_buf[]={0x0, 0x70, 0x1, 0xb9}; <] */
   /* int len1=17; */

    /* update(&T, 9, out_buf, len1, &der,&len2); */
    /* x509->cert_info.enc.enc = der; */
    /* x509->cert_info.enc.len =len2; */
	/* out = BIO_new(BIO_s_file()); */
	/* if (out == NULL) { */
		/* printf("out error\n"); */
	/* } */
	/* char *pemFile = "pem"; */
	/* if (BIO_write_filename(out, pemFile) <= 0) { */
		/* perror(pemFile); */
	/* } */
	/* int i = X509_2_PEM(private_key_file, out, x509); */
/* for(int i=0;i<len2;i++) */
    /* printf("%02x ",der[i]); */
/* printf("\n"); */
/* tlv(&T,&p,der); */
/* int len; */
/* unsigned char* v=ck_alloc(100); */
/* getvalue(T, 9, &len, &v); */
/* printf("%d\n",len); */
/* for(int i=0;i<len;i++) */
    /* printf("%02x ",v[i]); */
/* printf("\n"); */
    return 0;
 }
