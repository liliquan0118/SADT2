//#include"verify.h"
#define MAXLEN 10240
// typedef unsigned int u32;

//遍历所有的叶子节点，tag存放叶子节点的位置
void leaf(BiTree T,int **tag)
{
	if(T!=NULL)
	{
		if(T->lchild==NULL)
		{
			**tag=T->t;
			(*tag)++;
		}
		leaf(T->lchild,tag);
		leaf(T->rchild,tag);
	}
	return;
}

/*
 *从树T中找到值为buf的节点，len为buf的长度
 */
int find_node(BiTree T,unsigned char *buf,int**loc,int len)
{BiTree p=T;
	if(!p) return 0;
	int i,j;
	for(i=0;i<len;i++)
		if((p->pv)[i] != buf[i]) break;
	if ((i==len)&& (len ==p->v_len))
	{
		leaf(p->rchild,loc);
		return p->t;
	}
	else if ((j=find_node(p->lchild,buf,loc,len))&&j )
		return j;
	else return find_node(p->rchild,buf,loc,len);
}
 int parent(BiTree T,int lchild_t)
{
    BiTree p=T;
    if(!p) return -1;
    if(((p->lchild)&&(p->lchild->t==lchild_t)) || ((p->rchild)&&(p->rchild->t==lchild_t)))
        return p->t;
    int q=parent(p->lchild,lchild_t);
    if(q!=-1)
        return q;
    else return parent(p->rchild,lchild_t);

}
/*
 * Locate the position of the field in the der-format contents, given the field name.
 *in为der编码，name为字段名，叶子节点的位置放置在loc中
 */
int locate_field(unsigned char *in, char *name,int **loc){
	BiTree T=NULL;
	unsigned char *p=in;
	tlv(&T,&p,in);
    int field=0;
	if(strcmp(name,"version")==0) {
		BiTree node=T->lchild;
        if(node->lchild==NULL)
        {
            **loc=node->t;
            (*loc)++;
        }
        else{
            leaf(node->lchild,loc);
        }
        field=node->t;
        ClearBTree(&T);
		return field;
	}
	else if(strcmp(name,"serialnumber")==0) {
		BiTree node=T->lchild;
		node=node->rchild;
        if(node->lchild==NULL)
        {
            **loc=node->t;
            (*loc)++;
        }
        else{
            leaf(node->lchild,loc);
        }

        field=node->t;
        ClearBTree(&T);
		return field;
	}
	else if(strcmp(name,"signature")==0)
	{
		BiTree node=T->lchild;
		for(int i=0;i<2;i++)
			node=node->rchild;
        if(node->lchild==NULL)
        {
            **loc=node->t;
            (*loc)++;
        }
        else{
            leaf(node->lchild,loc);
        }

        field=node->t;
        ClearBTree(&T);
		return field;
	}
	else if(strcmp(name,"issuer")==0)
	{
		BiTree node=T->lchild;
		for(int i=0;i<3;i++)
			node=node->rchild;
        if(node->lchild==NULL)
        {
            **loc=node->t;
            (*loc)++;
        }
        else{
            leaf(node->lchild,loc);
        }

        field=node->t;
        ClearBTree(&T);
		return field;
	}
	else if(strcmp(name,"validity")==0)
	{
		BiTree node=T->lchild;
		for(int i=0;i<4;i++)
			node=node->rchild;
        if(node->lchild==NULL)
        {
            **loc=node->t;
            (*loc)++;
        }
        else{
            leaf(node->lchild,loc);
        }

        field=node->t;
        ClearBTree(&T);
		return field;
	}
	else if(strcmp(name,"subject")==0)
	{
		BiTree node=T->lchild;
		for(int i=0;i<5;i++)
			node=node->rchild;
        if(node->lchild==NULL)
        {
            **loc=node->t;
            (*loc)++;
        }
        else{
            leaf(node->lchild,loc);
        }

        field=node->t;
        ClearBTree(&T);
		return field;
	}
	else if(strcmp(name,"subjectPublicKeyInfo")==0)
	{
		BiTree node=T->lchild;
		for(int i=0;i<6;i++)
			node=node->rchild;
        if(node==NULL)
            return 0;
        if(node->lchild==NULL)
        {
            **loc=node->t;
            (*loc)++;
        }
        else{
            leaf(node->lchild,loc);
        }

        field=node->t;
        ClearBTree(&T);
		return field;
	}

else {

		BiTree node = T->lchild;
		while (node->rchild)
			node = node->rchild;
		char *oid;
		unsigned char *buf;
		int i;
		if (strcmp(name, "Authority Key Identifier") == 0) {
			//	const char oid[]={"2.5.29.19"};
			oid = "2.5.29.35";
		} else if (strcmp(name, "Basic Constraints") == 0) {
			oid = "2.5.29.19";
		} else if (strcmp(name, "Certificate Policies") == 0) {
			oid = "2.5.29.32";
		} else if (strcmp(name, "CRL Distribution Points") == 0) {
			oid = "2.5.29.31";
		} else if (strcmp(name, "Extended Key Usage") == 0) {
			oid = "2.5.29.37";
		} else if (strcmp(name, "Issuer Alternative Name") == 0) {
			oid = "2.5.29.18";
		} else if (strcmp(name, "Key Usage") == 0) {
			oid = "2.5.29.15";
		} else if (strcmp(name, "Name Constraints") == 0) {
			oid = "2.5.29.30";
		} else if (strcmp(name, "Policy Constraints") == 0) {
			oid = "2.5.29.36";
		} else if (strcmp(name, "Policy Mappings") == 0) {
			oid = "2.5.29.33";
		} else if (strcmp(name, "Private Key Usage Period") == 0) {
			oid = "2.5.29.16";
		} else if (strcmp(name, "Subject Alternative Name") == 0) {
			oid = "2.5.29.17";
		} else if (strcmp(name, "Subject Directory Attributes") == 0) {
			oid = "2.5.29.9";
		} else if (strcmp(name, "Subject Key Identifier") == 0) {
			oid = "2.5.29.14";
		} else if (strcmp(name, "Inhibit anyPolicy") == 0) {
			oid = "2.5.29.54";
		} else if (strcmp(name, "freshestCRL") == 0) {
			oid = "2.5.29.46";
		} else if (strcmp(name, "Authority Information Access") == 0) {
			oid = "1.3.6.1.5.5.7.1.1";
		} else if (strcmp(name, "Subject Information Access") == 0) {
			oid = "1.3.6.1.5.5.7.1.11";
		} else if (strcmp(name, "extension") == 0)//返回extension的位置
		{
			if (*(node->localt) == 0xa3)
            {

                field=node->v;
                ClearBTree(&T);
		        return field;
            }//返回a3下面一层的位置
			else
            {
            ClearBTree(&T);
		    return 0;
            }
		} else
        {
            ClearBTree(&T);
			return 0;
        }
		i = a2d_ASN1_OBJECT(NULL, 0, oid, -1);
		if (i <= 0)
        {
        ClearBTree(&T);
        return 0;
        }
		buf = (unsigned char *) ck_alloc(sizeof(unsigned char) * i + 1);
		int n = a2d_ASN1_OBJECT(buf, i, oid, -1);
		//for(int j=0;j<i;j++)
		//	printf("%02x ",buf[j]);
		//printf("\n");
		int lchild_t;
		if (*(node->localt) == 0xa3)//有extension字段
		{
			lchild_t = find_node(node, buf, loc, n);
			if (lchild_t) {

				 field = parent(node, lchild_t);
				ck_free(buf);
                ClearBTree(&T);
				if (field != -1)
					return field;
			}
            ck_free(buf);
            ClearBTree(&T);
			return 0;
		} else
            ck_free(buf);
            ClearBTree(&T);
			return 0;
	}
}

