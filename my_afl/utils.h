/*************************************************************************
	> File Name: utils.h
	> Author:
	> Mail:
	> Created Time: Wed 22 Aug 2018 02:54:42 PM +08
 ************************************************************************/

#ifndef _UTILS_H
#define _UTILS_H
#endif
#include<string.h>
//void print_hex(unsigned char *buf);
//int to_hex(int num, unsigned char* hex);
void print_hex(unsigned char *buff)
{
    for (int i=0;buff[i];i++)
        printf("%02x:",(unsigned char)buff[i]);
    printf("\n");
}

/*
 * Reverse a string
 * */
void reverse_str(unsigned char *src,int len){
    unsigned char *p = &src[0];
    unsigned char *q = &src[len-1];

    while(p<q){
        unsigned char tmp;
        tmp = *p;
        *p = *q;
        *q = tmp;
        p++;
        q--;
    }
}

/*
 * Show a demical num in the hex form
 * Note: The pointer hex should be initialized in advance
 * */
int to_hex(int num,unsigned char *hex){
    int cnt = 0;
    if(num ==0)
	{
	hex[0]=0x00;
	return 1;
	}
    while(num){
        hex[cnt] = num&0xff;
        num >>= 8;
        cnt++;
    }
    reverse_str(hex,cnt);
    return cnt;
}
int clean(char * tmp)
{
/*char *p=*tmp;
while(p)
{if(*p=='\n')
 (*p)='0';
p++;
}*/
for(int i=0;i<strlen(tmp);(tmp)++)
if(tmp[i]=='\n')
(tmp)[i]=' ';

return 0;
}
