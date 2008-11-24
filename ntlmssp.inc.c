/*
 * $Id: ntlmssp.inc.c,v 1.2.4.1 2003/02/23 15:56:26 casz Exp $
 *
 */

#define MAX_HOSTLEN 32
#define MAX_DOMLEN 32
#define MAX_USERLEN 32
#define RESP_LEN 24
#define NONCE_LEN 8

/* fhz, 01-10-15 : borrowed from samba code */
/* NTLMSSP negotiation flags */
#define NTLMSSP_NEGOTIATE_UNICODE          0x00000001
#define NTLMSSP_NEGOTIATE_OEM              0x00000002
#define NTLMSSP_REQUEST_TARGET             0x00000004
#define NTLMSSP_NEGOTIATE_SIGN             0x00000010
#define NTLMSSP_NEGOTIATE_SEAL             0x00000020
#define NTLMSSP_NEGOTIATE_LM_KEY           0x00000080
#define NTLMSSP_NEGOTIATE_NTLM             0x00000200
#define NTLMSSP_NEGOTIATE_00001000         0x00001000
#define NTLMSSP_NEGOTIATE_00002000         0x00002000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN      0x00008000
#define NTLMSSP_TARGET_TYPE_DOMAIN	   0x00010000
#define NTLMSSP_TARGET_TYPE_SERVER	   0x00020000
#define NTLMSSP_NEGOTIATE_NTLM2            0x00080000
#define NTLMSSP_NEGOTIATE_TARGET_INFO      0x00800000
#define NTLMSSP_NEGOTIATE_128              0x20000000
#define NTLMSSP_NEGOTIATE_KEY_EXCH         0x40000000

#define SMBD_NTLMSSP_NEG_FLAGS 0x000082b1
#define NTLM_NTLMSSP_NEG_FLAGS 0x00008206
/* 8201 8207 */

#define LEN_NTLMSSP_FLAGS 4
#define OFFSET_MSG1_NTLMSSP_FLAGS 12

struct ntlm_msg1 {
    unsigned char protocol[8];
    unsigned char type;         /* 1 */
    unsigned char zero1[3];
    unsigned char flags[2];
    unsigned char zero2[2];

    unsigned char dom_len[4];
    unsigned char dom_off[4];

    unsigned char host_len[4];
    unsigned char host_off[4];

#if 0
    unsigned char data[0];
#endif
} __attribute__((packed));

struct ntlm_msg2 {
    unsigned char protocol[8];
    unsigned char type;         /* 2 */
    unsigned char zero1[7];
    unsigned char msg_len[4];
    unsigned char flags[2];
    unsigned char zero2[2];

    unsigned char nonce[8];
    unsigned char zero3[8];
} __attribute__((packed));

struct ntlm_msg3 {
    unsigned char protocol[8];
    unsigned char type;         /* 3 */
    unsigned char zero1[3];

    unsigned char lm_len[4];
    unsigned char lm_off[4];

    unsigned char nt_len[4];
    unsigned char nt_off[4];

    unsigned char dom_len[4];
    unsigned char dom_off[4];

    unsigned char user_len[4];
    unsigned char user_off[4];

    unsigned char host_len[4];
    unsigned char host_off[4];

    unsigned char msg_len[4]; /* Win9x: data begins here! */

#if 0
    unsigned char data[0];
#endif
} __attribute__((packed));

struct ntlm_msg2_win9x {
    unsigned char protocol[8];
    unsigned char type;         /* 2 */
    unsigned char zero1[3];
    unsigned char dom_len1[2];
    unsigned char dom_len2[2];
    unsigned char dom_off[4];
    unsigned char flags[2];
    unsigned char zero2[2];

    unsigned char nonce[8];
    unsigned char zero3[8];
    unsigned char zero4[4];
    unsigned char msg_len[4];
    unsigned char dom[MAX_DOMLEN];
} __attribute__((packed));

/* size without dom[] : */
#define NTLM_MSG2_WIN9X_FIXED_SIZE (sizeof(struct ntlm_msg2_win9x)-MAX_DOMLEN)


typedef struct ntlmssp_info {
    int msg_type;
    unsigned char user[MAX_USERLEN + 1];
    unsigned char host[MAX_HOSTLEN + 1];
    unsigned char domain[MAX_DOMLEN + 1];
    unsigned char lm[RESP_LEN];
    unsigned char nt[RESP_LEN];
} ntlmssp_info_rec;

//#define little_endian_word(x) x[0] + (((unsigned)x[1]) << 8)
#define little_endian_word(x) x[0] + (((unsigned char)x[1]) << 8)
/* fhz 02-02-09: typecasting is needed for a generic use */
#define set_little_endian_word(x,y) (*((char *)x))=(y&0xff);*(((char*)x)+1)=((y>>8)&0xff)

static int 
ntlm_msg_type(unsigned char *raw_msg, unsigned msglen)
{
    struct ntlm_msg1 *msg = (struct ntlm_msg1 *) raw_msg;

    if (msglen < 9)
        return -1;
    if (strncmp(msg->protocol, "NTLMSSP", 8))
        return -1;
    return msg->type;
}

static int 
ntlm_extract_mem(request_rec * r, unsigned char *dst,
                 unsigned char *src, unsigned srclen,
                 unsigned char *off, unsigned char *len,
                 unsigned max)
{
    unsigned o = little_endian_word(off);
    unsigned l = little_endian_word(len);
    if (l > max)
        return -1;
    if (o >= srclen)
        return -1;
    if (o + l > srclen)
        return -1;
    src += o;
    while (l-- > 0)
        *dst++ = *src++;
    return 0;
}

static int 
ntlm_extract_string(request_rec * r, unsigned char *dst,
                    unsigned char *src, unsigned srclen,
                    unsigned char *off, unsigned char *len,
                    unsigned max)
{
    unsigned o = little_endian_word(off);
    unsigned l = little_endian_word(len);
    if (l > max)
        return -1;
    if (o >= srclen)
        return -1;
    if (o + l > srclen)
        return -1;
    src += o;
    while (l-- > 0) {
        /* +csz 2003/02/20 - En algunos casos vienen \0 entremedio */
        if ( *src != '\0' ) {
            *dst = *src;
            dst++;
        }
        src++;
    }
    *dst = 0;
    return 0;
}

static int
ntlm_put_in_unicode(unsigned char *dst,
                     unsigned char *src, unsigned srclen, unsigned max)
{
    unsigned l = srclen*2;
    if (l > max)
        l=max; /* fhz: bad very bad */
    while (l > 0) {
        /*  ASCII to unicode*/
        *dst++ = *src++;
	*dst++=0;
	l -=2;
    }
    return 0;



}

static int 
ntlm_extract_unicode(request_rec * r, unsigned char *dst,
                     unsigned char *src, unsigned srclen,
                     unsigned char *off, unsigned char *len,
                     unsigned max)
{
    unsigned o = little_endian_word(off);
    unsigned l = little_endian_word(len) / 2;   /* Unicode! */
    if (l > max)
        return -1;
    if (o >= srclen)
        return -1;
    if (o + l > srclen)
        return -1;
    src += o;
    while (l > 0) {
        /* Unicode to ASCII */
        *dst++ = *src;
        src += 2;
        l -= 2;
    }
    *dst = 0;
    return 0;
}

static int 
ntlm_msg1_getntlmssp_flags(request_rec * r, unsigned char *raw_msg,
                      unsigned char *ntlmssp_flags)
{
    struct ntlm_msg1 *msg = (struct ntlm_msg1 *) raw_msg;
    *ntlmssp_flags=little_endian_word(msg->flags);
    return 0;
}

static int 
ntlm_msg1_gethostname(request_rec * r, unsigned char *raw_msg,
                      unsigned msglen, unsigned char *hostname)
{
    struct ntlm_msg1 *msg = (struct ntlm_msg1 *) raw_msg;
    if (ntlm_extract_string(r, hostname, (char *) msg, msglen,
                            msg->host_off, msg->host_len, MAX_HOSTLEN))
		return 1;
    return 0;
}

static int 
ntlm_msg1_getdomainname(request_rec * r, unsigned char *raw_msg,
                        unsigned msglen, unsigned char *domainname)
{
    struct ntlm_msg1 *msg = (struct ntlm_msg1 *) raw_msg;
    if (ntlm_extract_string(r, domainname, (char *) msg,
                            msglen, msg->dom_off, msg->dom_len, MAX_DOMLEN))
        return 2;
    return 0;
}

static int 
ntlm_msg3_getlm(request_rec * r, unsigned char *raw_msg, unsigned msglen,
                unsigned char *lm)
{
    struct ntlm_msg3 *msg = (struct ntlm_msg3 *) raw_msg;
    if (ntlm_extract_mem(r, lm, (char *) msg, msglen, msg->lm_off,
                         msg->lm_len, RESP_LEN))
        return 4;
    return 0;
}

static int 
ntlm_msg3_getnt(request_rec * r, unsigned char *raw_msg, unsigned msglen,
                unsigned char *nt)
{
    struct ntlm_msg3 *msg = (struct ntlm_msg3 *) raw_msg;
    if (ntlm_extract_mem(r, nt, (char *) msg, msglen, msg->nt_off,
                         msg->nt_len, RESP_LEN)) 
	/* Win9x: we can't extract nt ... so we use lm... */
	    if (ntlm_extract_mem(r, nt, (char *) msg, msglen, msg->lm_off,
                         msg->lm_len, RESP_LEN)) 
		return 8;
    return 0;
}

static int 
ntlm_msg3_getusername(request_rec * r, unsigned char *raw_msg,
                      unsigned msglen, unsigned char *username,
		      unsigned ntlmssp_flags)
{
    struct ntlm_msg3 *msg = (struct ntlm_msg3 *) raw_msg;
    int c;
    if (ntlmssp_flags & NTLMSSP_NEGOTIATE_UNICODE) {
	    if (ntlm_extract_unicode(r, username, (char *) msg, msglen,
                             msg->user_off, msg->user_len, MAX_USERLEN))
		return 16;
	}
    else { /* ascii */
	    if (ntlm_extract_string(r, username, (char *) msg, msglen,
                             msg->user_off, msg->user_len, MAX_USERLEN))
		return 16;
	    else {
		/* Win9x client leave username in uppercase...fix it: */
		while (*username!=(unsigned char)NULL) {
			c=tolower((int)*username);
			*username=(unsigned char)c;
			username++;
		}
	    }
    }
    return 0;
}

static int 
ntlm_msg3_gethostname(request_rec * r, unsigned char *raw_msg, unsigned msglen,
                      unsigned char *hostname,unsigned ntlmssp_flags)
{
    struct ntlm_msg3 *msg = (struct ntlm_msg3 *) raw_msg;
    if (ntlmssp_flags & NTLMSSP_NEGOTIATE_UNICODE) {
	    if (ntlm_extract_unicode(r, hostname, (char *) msg, msglen,
                             msg->host_off, msg->host_len, MAX_HOSTLEN))
		return 0;  /* this one FAILS, but since the value is not used,
			    * we just pretend it was ok. */
	}
    else { /* ascii */
	    if (ntlm_extract_string(r, hostname, (char *) msg, msglen,
                             msg->host_off, msg->host_len, MAX_HOSTLEN))
		return 0;  /* this one FAILS, but since the value is not used,
			    * we just pretend it was ok. */
    }
    return 0;
}

static int 
ntlm_msg3_getdomainname(request_rec * r, unsigned char *raw_msg,
                        unsigned msglen, unsigned char *domainname,
			unsigned ntlmssp_flags)
{
    struct ntlm_msg3 *msg = (struct ntlm_msg3 *) raw_msg;
    if (ntlmssp_flags & NTLMSSP_NEGOTIATE_UNICODE) {
	    if (ntlm_extract_unicode(r, domainname, (char *) msg, msglen,
                             msg->dom_off, msg->dom_len, MAX_DOMLEN))
		return 64;
	}
    else { /* asii */
	    if (ntlm_extract_string(r, domainname, (char *) msg, msglen,
                             msg->dom_off, msg->dom_len, MAX_DOMLEN))
		return 64;
    }
    return 0;
}

static int 
ntlm_decode_msg(request_rec * r, struct ntlmssp_info *info,
                unsigned char *raw_msg, unsigned msglen,
		unsigned *ntlmssp_flags)
{
	unsigned char flags;
	int ret;
    switch (info->msg_type = ntlm_msg_type(raw_msg, msglen)) {
      case 1:
				ret = ntlm_msg1_getntlmssp_flags(r,raw_msg,&flags);	
				*ntlmssp_flags = (unsigned) flags;
        return ntlm_msg1_gethostname(r, raw_msg, msglen, info->host)
              + ntlm_msg1_getdomainname(r, raw_msg, msglen, info->domain);
      case 3:
          return ntlm_msg3_getlm(r, raw_msg, msglen, info->lm)
              + ntlm_msg3_getnt(r, raw_msg, msglen, info->nt)
              + ntlm_msg3_getusername(r, raw_msg, msglen, info->user,*ntlmssp_flags)
              + ntlm_msg3_gethostname(r, raw_msg, msglen, info->host,*ntlmssp_flags)
              + ntlm_msg3_getdomainname(r, raw_msg, msglen, info->domain,*ntlmssp_flags);
    }
    return -1;
}

static int 
ntlm_encode_msg2(unsigned char *nonce, struct ntlm_msg2 *msg)
{
    memset(msg, 0, sizeof(struct ntlm_msg2));
    strcpy(msg->protocol, "NTLMSSP");
    msg->type = 0x02;
    set_little_endian_word(msg->msg_len, sizeof(struct ntlm_msg2));
    set_little_endian_word(msg->flags, 0x8201);
    memcpy(msg->nonce, nonce, sizeof(msg->nonce));
    return 0;
}

static int 
ntlm_encode_msg2_win9x(unsigned char *nonce, struct ntlm_msg2_win9x *msg,char *domainname,unsigned ntlmssp_flags)
{
    unsigned int size,len,flags;

    memset(msg, 0, sizeof(struct ntlm_msg2_win9x));
    strcpy(msg->protocol, "NTLMSSP");
    msg->type = 0x02;
    if (ntlmssp_flags & NTLMSSP_NEGOTIATE_UNICODE) {
	   /* unicode case */

	    len=strlen(domainname);
	    ntlm_put_in_unicode((char *)msg->dom,domainname, 
		len, MAX_DOMLEN);
	    len=len*2;
	    if (len>MAX_DOMLEN)
		    len=MAX_DOMLEN; /* fhz: bad very bad */
	    flags=NTLM_NTLMSSP_NEG_FLAGS | NTLMSSP_NEGOTIATE_UNICODE;
    } else {
	    /* ascii case */
	    len=strlen(domainname);
	    if (len>MAX_DOMLEN)
		    len=MAX_DOMLEN; /* fhz: bad very bad */
	    strncpy(msg->dom,domainname,len); 
	    flags=NTLM_NTLMSSP_NEG_FLAGS;
    }
    size=NTLM_MSG2_WIN9X_FIXED_SIZE+len;
    set_little_endian_word(msg->dom_off, NTLM_MSG2_WIN9X_FIXED_SIZE);
    set_little_endian_word(msg->dom_len1,len);
    set_little_endian_word(msg->dom_len2,len);
    set_little_endian_word(msg->msg_len,size);
    set_little_endian_word(msg->flags,flags); 
    if (ntlmssp_flags & NTLMSSP_REQUEST_TARGET) 
    	 set_little_endian_word(msg->zero2, 0x01);  /* == set NTLMSSP_TARGET_TYPE_DOMAIN */
    	
    memcpy(msg->nonce, nonce, sizeof(msg->nonce));
    return size;
}
