
#ifndef MY_OPENSSL_TLV_H
#define MY_OPENSSL_TLV_H
// #include <stdio.h>
// #include <string.h>
// #include <stdlib.h>
#include <stdbool.h>
#include "utils.h"
// #include<time.h>
// #include<sys/time.h>
bool isext;//0-非扩展  1-扩展
bool first=1;
typedef struct BiTNode{
    struct BiTNode * lchild;
    struct BiTNode * rchild;
    //TLV *tlv;
    int t;//T的位置
    int v;//V的位置
    //  int parent;//父节点位置
    unsigned char*localt;//T的位置
    int v_len;
    unsigned char*pv;
}BiTNode;
typedef BiTNode* BiTree;
//TLV匹配的递归
int tlv(BiTree *T,unsigned char**p,unsigned char*der){
    // unsigned char*der=*p;
    if(!(*T))
    { *T=ck_alloc(sizeof(BiTNode)*1);
        (*T)->lchild=NULL;
        (*T)->rchild=NULL;
        //(*T)->parent=0;
    }

    (*T)->t=(*p)-der;
    (*T)->localt=*p;
    //(*T)->parent=0;
    //unsigned char type=*(*p);//type
    unsigned char type=*(*p);
    (*p)++;
    unsigned char len0=*(*p)++;//len
    int len=len0;
    int lem=0;
    int l=2;
    if(len0>0x80){
        int tn2=len0-0x80;//length的字节数
        unsigned char tl;
        len=0;
        //计算length的值
        for(int i=0;i<tn2;i++){
            tl=*(*p);
            (*p)++;
            len*=256;
            len+=tl;
        }
        l+=len0-0x80;
    }
    (*T)->v=*p-der;
    (*T)->pv=*p;
    (*T)->v_len=len;
    if(type<0xa0){
        //Structured Types
        if(type==0x30||type==0x31){
            int dlen=len;
            if(dlen>0)
            {
                /// (*T)->lchild=(BiTree)malloc(sizeof(BiTNode)*1);
                // (*T)->lchild->parent=(*T)->t;
                dlen-=tlv(&((*T)->lchild),p,der);
            }

            BiTNode * bt=(*T)->lchild;
            //遍历嵌套tlv
            while(dlen>0){
                // bt->rchild=(BiTree)malloc(sizeof(BiTNode)*1);
                // bt->rchild->parent=bt->parent;
                dlen-=tlv(&(bt->rchild),p,der);
                bt=bt->rchild;
            }
        }
        //extension 字段
        else if(isext==1 && type==4)
        { isext=0;
            int dlen=len;
            if(dlen>0)
            {
                // (*T)->lchild=(BiTree)malloc(sizeof(BiTNode)*1);
                // (*T)->lchild->parent=(*T)->t;
                dlen-=tlv(&((*T)->lchild),p,der);
            }

            BiTNode * bt=(*T)->lchild;
            while(dlen>0){
                //  bt->rchild=(BiTree)malloc(sizeof(BiTNode)*1);
                // bt->rchild->parent=bt->parent;
                dlen-=tlv(&(bt->rchild),p,der);
                bt=bt->rchild;
            }
            isext=1;
        }
        //Primitive Types
        else{
            for(int i=0;i<len;i++)
                (*p)++;
        }

    }
    //EXPLICIT tag
    else{
        lem=type-0xa0;
        if(lem==3 && first==1) {
            isext=1;
            first=0;
            //   (*T)->lchild=(BiTree)malloc(sizeof(BiTNode)*1);
            // (*T)->lchild->parent=(*T)->t;
            tlv(&((*T)->lchild),p,der);
            isext=0;
            first=1;
        }
        else{
            int dlen=len;
            if(dlen>0) {
                //(*T)->lchild=(BiTree)malloc(sizeof(BiTNode)*1);
                //(*T)->lchild->parent=(*T)->t;
                dlen -= tlv(&((*T)->lchild), p, der);
            }
            BiTNode * bt=(*T)->lchild;
            while(dlen>0){
                //bt->rchild=(BiTree)malloc(sizeof(BiTNode)*1);
                //bt->rchild->parent=bt->parent;
                dlen-=tlv(&(bt->rchild),p,der);
                bt=bt->rchild;
            }
        }
    }
    //返回字段总字节数
    return l+len;
}

void PreOrderTraverse(BiTree T)
{ //printf("遍历\n");
    if(T==NULL)
        return;
    printf("%02X %02X--->",*(T->localt),T->v_len);// 显示结点数据，可以更改为其它对结点操作
    PreOrderTraverse(T->lchild); // 再先序遍历左子树
    PreOrderTraverse(T->rchild); // 最后先序遍历右子树
}
int add;
/*将t位置的节点的值mutate为mu，update tree T，mu_len为mu的length，d保存certinfo的der编码，totallen为d的length*/
int  update(BiTree *T,long t,unsigned char *mu,int mu_len,unsigned char **d,long* totallen)
{

    if(!(*T)) return 0;
    int clen;
    int  v_add, l_add;
    int cnt;   //bytes of Length in TLV after mutation
    unsigned char buf[30]; //data buffer to store the Length data in TLV
    int len_bytes =(*T)->v-(*T)->t-1 ;
    long next = (*T)->v+(*T)->v_len; //field offset next to the muated one
    memset(buf,0,30);
    long total_len=*totallen;
    //	if(strcmp((*T)->s,p)==0 && (*d)[(*T)->t]==tag)
    if((*T)->t==t)
    {
        clen=mu_len;
        v_add = clen-(*T)->v_len;
        cnt = to_hex(clen,buf);
        total_len=*totallen;
        if(clen>127){
            memmove(buf+1,buf,cnt);
            buf[0] = 0x80+cnt;
            cnt++;
        }
        l_add = cnt - len_bytes;
        add = v_add+l_add;
        if(add>0){
            *d = ck_realloc(*d,total_len+add);
            memmove(*d+next+add,*d+next,total_len-next);    //把该字段后面的内容向后移动
            memmove(*d+(*T)->t+1,buf,cnt); //update Length in TLV
            memmove(*d+(*T)->t+1+cnt,mu,clen); //update Value in TLV
            *totallen=total_len+add;
        }else {
            total_len=*totallen;
            memmove(*d+(*T)->t+1,buf,cnt); //update Length in TLV
            memmove(*d+(*T)->t+1+cnt,mu,clen); //update Value in TLV
            if(add<0){
                memmove(*d+next+add,*d+next,total_len-next); //把该字段后面的内容向前移动
                *d =ck_realloc(*d,total_len+add);
                *totallen=total_len+add;

            }
        }

        return 1;
    }
    if (update(&((*T)->lchild),t,mu,mu_len,d,totallen))
    {       int len =(*T)->v_len+add;
        unsigned char buf[30];
        memset(buf,0,30);
        int  m_len = to_hex(len,buf);
        if(len>127){
            memmove(buf+1,buf,m_len);
            buf[0] = 0x80+m_len;
            m_len++;
        }
        int move=m_len-len_bytes;
        total_len=*totallen;
        add+=move;
        if(move>0)
        {*d = ck_realloc(*d,total_len+move);
            memmove(*d+(*T)->v+move,*d+(*T)->v,total_len-(*T)->v);    //把该字段后面的内容向后移动
            memmove(*d+(*T)->t+1,buf,m_len); //update Length in TLV
            *totallen=total_len+move;
        }
        else{

            if(move<0)
            {
                memmove(*d+(*T)->t+1,buf,m_len); //update Length in TLV
                memmove(*d+(*T)->v+move,*d+(*T)->v,total_len-(*T)->v); //把该字段后面的内容向前移动
                *d = ck_realloc(*d,total_len+move);
                *totallen=total_len+move;

            } else{
                memmove(*d+(*T)->t+1,buf,m_len); //update Length in TLV
                *totallen=total_len;
            }

        }
        return 1;
    }
    if(update(&((*T)->rchild), t,mu,mu_len,d,totallen)) return 1;
    return 0;


}

//查找开始位置为t的节点，若存在将值的长度放在tlen中，tag值放在tag中
int find(BiTree T,long t,int* tlen,unsigned char *tag, unsigned char **v)
{BiTree p=T;
    if(!p) return 0;
    if(p->t==t)
    {*tlen=p->v_len;
        *tag=*(p->localt);
        for(int j=0;j<*tlen;j++)
            *(*v+j)=*(p->pv+j);
        return 1;
    }
    if(find(p->lchild,t,tlen,tag,v) || find(p->rchild,t,tlen,tag,v))
        return 1;
    return 0;
}
//查找开始位置为t的节点，将节点的tlv的位置分别存在tlen、tag，v中
int find_tlv(BiTree T,long t,int* tlen,int *tag, int *v)
{BiTree p=T;
    if(!p) return 0;
    if(p->t==t)
    {
        *tlen=p->v_len;
        *tag=p->t;
        *v=p->v;
        return 1;
    }
    if(find_tlv(p->lchild,t,tlen,tag,v) || find_tlv(p->rchild,t,tlen,tag,v))
        return 1;
    return 0;
}


int getvalue(BiTree T,long t,int* tlen, unsigned char **v)
{
    BiTree p=T;
    if(!p) return 0;
    if(p->t==t)
    {
        *tlen=p->v_len;
        for(int j=0;j<*tlen;j++)
            *(*v+j)=*(p->pv+j);
        return 1;
    }
    if(getvalue(p->lchild,t,tlen,v) || getvalue(p->rchild,t,tlen,v))
        return 1;
    return 0;
}

int getfield(BiTree T,long t,unsigned char * der,int* tlen, unsigned char **v)
{
    BiTree p=T;
    if(!p) return 0;
    if(p->t==t)
    {
        // *tlen=p->v_len;

        for(int k=p->t;k<p->v;k++)
            *(*v+k-p->t)=*(der+k);
        int x=p->v-p->t;
        *tlen=p->v_len+x;
        for(int j=0;j<*tlen;j++)
            *(*v+j+x)=*(p->pv+j);
        return 1;
    }
    if(getfield(p->lchild,t,der,tlen,v) || getfield(p->rchild,t,der,tlen,v))
        return 1;
    return 0;
}
void ClearBTree(BiTree* BT)
{
    if (*BT != NULL)
    {
        ClearBTree(&((*BT)->lchild ));//删除左子树
        ClearBTree(&((*BT)->rchild));//删除右子树
        ck_free(*BT);            //释放根结点
        *BT = NULL;           //置根指针为空
    }
}

 int Gen_numStr(unsigned char **str,int len)
{
   int i,flag;
     struct timeval tpstart;

   //srand(time(0));//通过时间函数设置随机数种子，使得每次运行结果随机。
    for(i = 0; i < len; i ++)
    {
        gettimeofday(&tpstart,NULL);
        srand(tpstart.tv_usec);
    	(*str)[i] = rand()%10 + '0';
    }
   (*str)[i]='\0';
    return 0;
}
int insert_field(BiTree *T,int field, unsigned char **der,long *totallen)//T为der的tlv tree,field是要插入字段的位置,
{
	if(!(*T)) return 0;
	if((*T)->t==field)
	{
		int field_len;//整个字段的长度;
		int next;//该字段后面一个字段的位置
		next=(*T)->v+(*T)->v_len;
		field_len=next-(*T)->t;
        long total_len=*totallen;
		*der = (unsigned char *)ck_realloc(*der, sizeof(unsigned char)*(total_len+field_len));
		memmove(*der+next,*der+(*T)->t,total_len-(*T)->t);
		*totallen=total_len+field_len;
		return field_len;

	}
	int vlen_add=insert_field(&((*T)->lchild),field,der,totallen);//增加的长度
	if(vlen_add)
	{
		int new_vlen=(*T)->v_len+vlen_add;//插入字段后其父节点的值的长度
		unsigned char buf[30];
		memset(buf,0,30);
		int  new_len_bytes = to_hex(new_vlen,buf);//new_vlen转成十六进制所需要的字节数
		if(new_vlen>127){
			memmove(buf+1,buf,new_len_bytes);
			buf[0] = 0x80+new_len_bytes;
			new_len_bytes++;
		}
		int len_bytes =(*T)->v-(*T)->t-1 ;
		int move=new_len_bytes-len_bytes;
		if(move>0)
		{
			int total_len=*totallen;
			*der = (unsigned char *)ck_realloc(*der, sizeof(unsigned char)*(total_len+move));
			memmove(*der+(*T)->v+move,*der+(*T)->v,total_len-(*T)->v);    //把该字段后面的内容向后移动
			memmove(*der+(*T)->t+1,buf,new_len_bytes); //update Length in TLV
			*totallen=total_len+move;
		}
		else{
			memmove(*der+(*T)->t+1,buf,new_len_bytes); //update Length in TLV
		}
		return (vlen_add+move);
	}
	int rvlen_add = insert_field(&((*T)->rchild),field,der,totallen);
	if(rvlen_add)
		return rvlen_add;
	return 0;
}


int delete_field(BiTree *T,int field, unsigned char **der,long *totallen)//T为der的tlv tree,field是要插入字段的位置,
{
    if(!(*T)) return 0;
    if((*T)->t==field)
    {
        int field_len;//整个字段的长度;
        int next;//该字段后面一个字段的位置
        next=(*T)->v+(*T)->v_len;
        field_len=next-(*T)->t;
        long total_len=*totallen;
        memmove(*der+field,*der+next,total_len-next);
        //*der=(unsigned char *) realloc(*der,sizeof(unsigned char)*3);
        *der = (unsigned char *)ck_realloc(*der, sizeof(unsigned char)*(total_len-field_len));
        *totallen=total_len-field_len;
        return field_len;

    }
    int vlen_del=delete_field(&((*T)->lchild),field,der,totallen);//减少的长度
    if(vlen_del)
    {
        int new_vlen=(*T)->v_len-vlen_del;//删除字段后其父节点的值的长度
        unsigned char buf[30];
        memset(buf,0,30);
        int  new_len_bytes = to_hex(new_vlen,buf);//new_vlen转成十六进制所需要的字节数
        if(new_vlen>127){
            memmove(buf+1,buf,new_len_bytes);
            buf[0] = 0x80+new_len_bytes;
            new_len_bytes++;
        }
        int len_bytes =(*T)->v-(*T)->t-1 ;
        int move=new_len_bytes-len_bytes;
        if(move==0) {
            memmove(*der + (*T)->t + 1, buf, new_len_bytes); //update Length in TLV
        }
        if(move<0)
        {
            int total_len=*totallen;
            memmove(*der + (*T)->t + 1, buf, new_len_bytes);
            memmove(*der+(*T)->v+move,*der+(*T)->v,total_len-(*T)->v);    //把该字段后面的内容向后移动
            *der = (unsigned char *)ck_realloc(*der, sizeof(unsigned char)*(total_len+move));
            *totallen=total_len+move;
        }
        return (vlen_del-move);
    }
    int rvlen_del = delete_field(&((*T)->rchild),field,der,totallen);
    if(rvlen_del)
        return rvlen_del;
    return 0;
}



int insert(BiTree *T,int field, unsigned char *mu,int mu_len,unsigned char **der,long *totallen)//T为der的tlv tree,field是要插入字段的位置,
{
	if(!(*T)) return 0;
	if((*T)->t==field)
	{
		int next;//该字段后面一个字段的位置
		next=(*T)->v+(*T)->v_len;
        long total_len=*totallen;
		*der = (unsigned char *)ck_realloc(*der, sizeof(unsigned char)*(total_len+mu_len));
		memmove(*der+(*T)->t+mu_len,*der+(*T)->t,total_len-(*T)->t);
		memmove(*der+(*T)->t,mu,mu_len);
		*totallen=total_len+mu_len;
		return mu_len;

	}
	int vlen_add=insert(&((*T)->lchild),field,mu,mu_len,der,totallen);//增加的长度
	if(vlen_add)
	{
		int new_vlen=(*T)->v_len+vlen_add;//插入字段后其父节点的值的长度
		unsigned char buf[30];
		memset(buf,0,30);
		int  new_len_bytes = to_hex(new_vlen,buf);//new_vlen转成十六进制所需要的字节数
		if(new_vlen>127){
			memmove(buf+1,buf,new_len_bytes);
			buf[0] = 0x80+new_len_bytes;
			new_len_bytes++;
		}
		int len_bytes =(*T)->v-(*T)->t-1 ;
		int move=new_len_bytes-len_bytes;
		if(move>0)
		{
			int total_len=*totallen;
			*der = (unsigned char *)ck_realloc(*der, sizeof(unsigned char)*(total_len+move));
			memmove(*der+(*T)->v+move,*der+(*T)->v,total_len-(*T)->v);    //把该字段后面的内容向后移动
			memmove(*der+(*T)->t+1,buf,new_len_bytes); //update Length in TLV
			*totallen=total_len+move;
		}
		else{
			memmove(*der+(*T)->t+1,buf,new_len_bytes); //update Length in TLV
		}
		return (vlen_add+move);
	}
	int rvlen_add = insert(&((*T)->rchild),field,mu,mu_len,der,totallen);
	if(rvlen_add)
		return rvlen_add;
	return 0;
}

#endif //MY_OPENSSL_X509TOPEM_H




