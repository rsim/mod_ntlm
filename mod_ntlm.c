/* 
 * mod_ntlm.c: NTLM authentication module for Apache/Unix
 * Version 0.2
 * 
 *     "This product includes software developed by the Apache Group
 *     for use in the Apache HTTP server project (http://www.apache.org/)."
 * 
 * Based on 
 * mod_ntlm.c for Win32 by Tim Costello <tim.costello@bigfoot.com>
 * pam_smb by Dave Airlie <Dave.Airlie@ul.ie>
 *
 * This code is copyright 2000 Andreas Gal <agal@uwsp.edu>.
 * Visit http://modntlm.sourceforge.net/ for code updates.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS`` AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES ARE DISCLAIMED. 
 * 
 * This code may be freely distributed, as long the above notices are
 * reproduced.
 *
 *  $Id: mod_ntlm.c,v 0.2 Apache 2.x 2004/03/08 09:44:02 mc Exp $
 *  
 */

#define VERSION "mod_ntlm2-0.2"

#define USE_APACHE_PROVIDED_UU_FUNCTIONS
#define LOG

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "mod_ntlm.h"

#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ntlmssp.inc.c"

#include "smbval/byteorder.h"
#include "smbval/std-defines.h"
#include "smbval/std-includes.h"
#include "smbval/smblib-common.h"
#include "smbval/smblib-priv.h"
#include "smbval/rfcnb-common.h"
#include "smbval/rfcnb-error.h"
#include "smbval/rfcnb-priv.h"
#include "smbval/rfcnb-util.h"
#include "smbval/rfcnb-io.h"
#include "smbval/rfcnb.h"
#include "smbval/valid.h"
#include <stdarg.h>

/* We exclude SOLARIS here also because for some reason unixd_set_global_mutex_perms hangs 
** if the process is started by root */
#if !defined(OS2) && !defined(WIN32) && !defined(BEOS)  && !defined(NETWARE) && !defined(SOLARIS2)
#include "unixd.h"
#define MOD_NTLM_SET_MUTEX_PERMS /* XXX Apache should define something */
#endif

static void log(const request_rec * r, int level, const char *format,...)
{
    va_list ap;
    char *s;
	int iLen;

    if ((s = (char *) malloc(2048)) == NULL)
        return;
	iLen = sprintf(s, "%u %u %s - ", (unsigned) r->connection, (unsigned) getpid(), r->uri);
    va_start(ap, format);
    vsprintf(s + iLen, format, ap);
    va_end(ap);
    ap_log_rerror(APLOG_MARK, level, 0, r, s);
    free(s);
}

static server_rec* pServer = NULL;
static void slog(int level, const char *format,...) {
	va_list ap;
	char* s;
	int iLen;
	
    if ((s = (char *) malloc(2048)) == NULL)
        return;
	
	iLen = sprintf(s, "%u - ", (unsigned) getpid());
    va_start(ap, format);
    vsprintf(s + iLen, format, ap);
    va_end(ap);
    ap_log_error(APLOG_MARK, level, 0, pServer, s);
    free(s);
}

#include "smbval/rfcnb-io.inc.c"
#include "smbval/rfcnb-util.inc.c"
#include "smbval/session.inc.c"
#include "smbval/smbdes.inc.c"
#include "smbval/smbencrypt.inc.c"
#include "smbval/smblib-util.inc.c"
#include "smbval/smblib.inc.c"
#include "smbval/valid.inc.c"

static const command_rec ntlm_cmds[] = {
    AP_INIT_FLAG
    ( "NTLMAuth",  ap_set_flag_slot,
      (void *)APR_OFFSETOF(ntlm_config_rec, ntlm_on),
      OR_AUTHCFG,
      "set to 'on' to activate NTLM authentication here" ),

    AP_INIT_TAKE1
    ("AuthNTGroups", ap_set_string_slot,
      (void *)APR_OFFSETOF(ntlm_config_rec, ntlm_grpfile),
      OR_AUTHCFG,
       "text file containing (NT) group names and member user IDs"),

    AP_INIT_FLAG
    ( "NTLMBasicAuth", ap_set_flag_slot,
      (void *)APR_OFFSETOF(ntlm_config_rec, ntlm_basic_on),
      OR_AUTHCFG,
      "set to 'on' to allov Basic authentication too" ),

    AP_INIT_TAKE1
    ( "NTLMBasicRealm", ap_set_string_slot,
      (void *)APR_OFFSETOF(ntlm_config_rec, ntlm_basic_realm),
      OR_AUTHCFG,
      "realm to use for Basic authentication" ),

    AP_INIT_FLAG
    ( "NTLMAuthoritative", ap_set_flag_slot,
      (void *)APR_OFFSETOF(ntlm_config_rec, ntlm_authoritative),
      OR_AUTHCFG,
      "set to 'off' to allow access control to be passed along to lower "
      "modules if the UserID is not known to this module" ),

    AP_INIT_TAKE1
    ( "NTLMDomain", ap_set_string_slot,
      (void *)APR_OFFSETOF(ntlm_config_rec, ntlm_domain),
      OR_AUTHCFG,
      "set to the domain you want users authenticated against for cleartext "
      "authentication - if not specified, the local machine, then all trusted "
      " domains are checked" ),

    AP_INIT_TAKE1
    ( "NTLMServer", ap_set_string_slot,
      (void *)APR_OFFSETOF(ntlm_config_rec, ntlm_server),
      OR_AUTHCFG,
      "set to the NT server to contact to authenticate users" ),

    AP_INIT_TAKE1
    ( "NTLMBackup", ap_set_string_slot,
      (void *)APR_OFFSETOF(ntlm_config_rec, ntlm_backup),
      OR_AUTHCFG,
      "set to the alternate NT server to contact to authenticate users" ),

    AP_INIT_TAKE1
    ( "NTLMLockFile", ap_set_string_slot,
      (void *)APR_OFFSETOF(ntlm_config_rec, ntlm_lockfile),
      OR_AUTHCFG,
      "set to the lock file that is used to prevent simutaneous contacts to DC" ),

    { NULL }
};

static apr_global_mutex_t *ntlm_lock = NULL;
static char ntlm_lock_name[L_tmpnam];

static apr_status_t cleanup_ntlmlock(void* not_used) {
    slog(APLOG_INFO, "Cleaning up ntlm_lock");
	if(ntlm_lock) {
		apr_global_mutex_destroy(ntlm_lock);
		ntlm_lock = NULL;
	}
	return APR_SUCCESS;
}

static void log_error_and_cleanup(char *msg, apr_status_t sts, server_rec *s) {
  ap_log_error(APLOG_MARK, APLOG_ERR, sts, s, "NTLM: %s", msg);
	cleanup_ntlmlock(NULL);
}

static int initialize_module(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {
	apr_status_t sts;
	void *data;
	const char *userdata_key = "mod_ntlm_init";

	/* initialize_module() will be called twice, and if it's a DSO
	** then all static data from the first call will be lost. Only
	** set up our static data on the second call. */
		
	if(pServer == NULL) pServer = s;
	apr_pool_userdata_get(&data, userdata_key, s->process->pool);
	if (!data) {
		slog(APLOG_DEBUG, "Calling initialize_module first time");
		apr_pool_userdata_set((const void *)1, userdata_key, apr_pool_cleanup_null, s->process->pool);
		return OK;
	}
	tmpnam(ntlm_lock_name);
	/* FIXME: get the client_lock_name from a directive so we're portable
	** to non-process-inheriting operating systems, like Win32. */
	slog(APLOG_DEBUG, "Creating global mutex ntlm_lock");
	sts = apr_global_mutex_create(&ntlm_lock, ntlm_lock_name, APR_LOCK_DEFAULT, p);
	if (sts != APR_SUCCESS) {
		log_error_and_cleanup("failed to create lock (ntlm_lock)", sts, s);
		return !OK;
	}

#ifdef MOD_NTLM_SET_MUTEX_PERMS
	slog(APLOG_DEBUG, "Setting permission on global mutex");
	sts = unixd_set_global_mutex_perms(ntlm_lock);
	if (sts != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, sts, s,
							"mod_ntlm: Could not set permissions on "
							"ntlm_lock; check User and Group directives");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
#endif

	slog(APLOG_DEBUG, "Setting up cleanup function for ntlm_lock");
	apr_pool_cleanup_register(p, (void *)s, cleanup_ntlmlock, apr_pool_cleanup_null);
	return OK;
}

static void initialize_child(apr_pool_t *p, server_rec *s) {
	apr_status_t sts;

	/* FIXME: get the client_lock_name from a directive so we're portable
	** to non-process-inheriting operating systems, like Win32. */
	slog(APLOG_DEBUG, "Calling apr_global_mutex_child_init with lockfile %s", ntlm_lock_name);
	sts = apr_global_mutex_child_init(&ntlm_lock, ntlm_lock_name, p);
	if (sts != APR_SUCCESS) {
		log_error_and_cleanup("failed to create lock (ntlm_lock)", sts, s);
		return;
	}
	return;
}

static void * 
create_ntlm_dir_config( apr_pool_t *p, char *d)
{
    ntlm_config_rec *crec = (ntlm_config_rec *) apr_pcalloc(p, sizeof(ntlm_config_rec));

    /* Set the defaults. */
    crec->ntlm_authoritative = 1;
    crec->ntlm_on = 0;
    crec->ntlm_basic_on = 0;
    crec->ntlm_basic_realm = "REALM";
    crec->ntlm_server = "SERVER";
    crec->ntlm_backup = "";
    crec->ntlm_domain = "DOMAIN";
    crec->ntlm_grpfile = NULL; /* rit, group file added */
	crec->ntlm_lockfile = "/tmp/ntlm.lck";
	apr_thread_mutex_create(&crec->ntlm_mutex, APR_THREAD_MUTEX_DEFAULT, p);

    return crec;
}

#ifdef USE_APACHE_PROVIDED_UU_FUNCTIONS

static void *
uudecode_binary(apr_pool_t *p, const char *bufcoded, int *nbytesdecoded)
{
    char *decoded;

    decoded = (char *) apr_palloc(p, 1 + apr_base64_decode_len(bufcoded));
    *nbytesdecoded = apr_base64_decode(decoded, bufcoded);
    decoded[*nbytesdecoded] = '\0'; /* make binary sequence into string */

    return decoded;
}

static char *
uuencode_binary(apr_pool_t *p, unsigned char *string, int len)
{
    char *encoded;

    encoded = (char *) apr_palloc(p, 1 + apr_base64_encode_len(len));
    len = apr_base64_encode(encoded, string, len);
    encoded[len] = '\0'; /* make binary sequence into string */

    return encoded;
}

#else
/* UUENCODE / DECODE TABLES */

static const unsigned char pr2six[256] =
{
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, 52, 53, 54,
    55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0, 1, 2, 3,
    4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

static const char basis_64[]
    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* 
 * UUENCODE / DECODE routines below taken from apache source code
 */
static void *
uudecode_binary(apr_pool_t * p, const char *bufcoded, int *nbytesdecoded)
{
    register const unsigned char *bufin;
    register char *bufplain;
    register unsigned char *bufout;
    register int nprbytes;

    /* Strip leading whitespace. */

    while (*bufcoded == ' ' || *bufcoded == '\t')
        bufcoded++;

    /* Figure out how many characters are in the input buffer.
     * Allocate this many from the per-transaction pool for the
     * result. */
#ifndef CHARSET_EBCDIC
    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63) ;
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    *nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufplain = apr_palloc(p, *nbytesdecoded + 1);
    bufout = (unsigned char *) bufplain;

    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 0) {
        *(bufout++) =
            (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
        *(bufout++) =
            (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
        *(bufout++) =
            (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
        bufin += 4;
        nprbytes -= 4;
    }

    if (nprbytes & 03) {
        if (pr2six[bufin[-2]] > 63)
            *nbytesdecoded -= 2;
        else
            *nbytesdecoded -= 1;
    }
    bufplain[*nbytesdecoded] = '\0';
#else /* CHARSET_EBCDIC */
    bufin = (const unsigned char *) bufcoded;
    while (pr2six[os_toascii[(unsigned char) *(bufin++)]] <= 63) ;
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    *nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufplain = apr_palloc(p, *nbytesdecoded + 1);
    bufout = (unsigned char *) bufplain;

    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 0) {
        *(bufout++)
            = os_toebcdic[(unsigned char) (pr2six[os_toascii[*bufin]]
                                           << 2 | pr2six[os_toascii[bufin[1]]]
                                           >> 4)];
        *(bufout++)
            = os_toebcdic[(unsigned char) (pr2six[os_toascii[bufin[1]]]
                                           << 4 | pr2six[os_toascii[bufin[2]]]
                                           >> 2)];
        *(bufout++)
            = os_toebcdic[(unsigned char) (pr2six[os_toascii[bufin[2]]]
                                         << 6 | pr2six[os_toascii[bufin[3]]])];
        bufin += 4;
        nprbytes -= 4;
    }

    if (nprbytes & 03) {
        if (pr2six[os_toascii[bufin[-2]]] > 63)
            *nbytesdecoded -= 2;
        else
            *nbytesdecoded -= 1;
    }
    bufplain[*nbytesdecoded] = '\0';
#endif /* CHARSET_EBCDIC */
    return bufplain;
}

static char *
uuencode_binary(apr_pool_t *a, unsigned char *string, int len)
{
    int i;
    char *p;
    char *encoded = (char *) apr_palloc(a, ((len + 2) / 3 * 4) + 1);

    p = encoded;
#ifndef CHARSET_EBCDIC
    for (i = 0; i < len - 2; i += 3) {
        *p++ = basis_64[(string[i] >> 2) & 0x3F];
        *p++ = basis_64[((string[i] & 0x3) << 4)
                       | ((int) (string[i + 1] & 0xF0) >> 4)];
        *p++ = basis_64[((string[i + 1] & 0xF) << 2)
                       | ((int) (string[i + 2] & 0xC0) >> 6)];
        *p++ = basis_64[string[i + 2] & 0x3F];
    }
    if (i < len) {
        *p++ = basis_64[(string[i] >> 2) & 0x3F];
        *p++ = basis_64[((string[i] & 0x3) << 4)
                       | ((int) (string[i + 1] & 0xF0) >> 4)];
        if (i == (len - 2))
            *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
        else
            *p++ = '=';
        *p++ = '=';
    }
#else /* CHARSET_EBCDIC */
    for (i = 0; i < len - 2; i += 3) {
        *p++ = basis_64[(os_toascii[string[i]] >> 2) & 0x3F];
        *p++ = basis_64[((os_toascii[string[i]] & 0x3) << 4)
                       | ((int) (os_toascii[string[i + 1]] & 0xF0) >> 4)];
        *p++ = basis_64[((os_toascii[string[i + 1]] & 0xF) << 2)
                       | ((int) (os_toascii[string[i + 2]] & 0xC0) >> 6)];
        *p++ = basis_64[os_toascii[string[i + 2]] & 0x3F];
    }
    if (i < len) {
        *p++ = basis_64[(os_toascii[string[i]] >> 2) & 0x3F];
        *p++ = basis_64[((os_toascii[string[i]] & 0x3) << 4)
                       | ((int) (os_toascii[string[i + 1]] & 0xF0) >> 4)];
        if (i == (len - 2))
            *p++ = basis_64[((os_toascii[string[i + 1]] & 0xF) << 2)];
        else
            *p++ = '=';
        *p++ = '=';
    }
#endif /* CHARSET_EBCDIC */

    *p = '\0';
    return encoded;
}
#endif /* USE_APACHE_PROVIDED_UU_FUNCTIONS */

static ntlm_connection_rec* get_ntlm_connection(conn_rec* c) {
	char key[20];
	ntlm_connection_rec* ntlm_connection;
	sprintf(key, "%u", c->id);
	apr_pool_userdata_get((void**) &ntlm_connection, key, c->pool); 
	return ntlm_connection;
}

static apr_status_t 
cleanup_ntlm_connection(void *conn)
{
	ntlm_connection_rec* ntlm_connection;
	ntlm_connection = get_ntlm_connection(conn);
	if(ntlm_connection == NULL) slog(APLOG_INFO,"ntlm_connection is NULL in cleanup");
	slog(APLOG_INFO,"NTLMXX-Clearing NTLM connection: %u id: %u", ntlm_connection, ((conn_rec*)conn)->id );
   	if (ntlm_connection->handle) {
       	NTLM_Disconnect(ntlm_connection->handle);
       	ntlm_connection->handle = NULL;
   	}
    return APR_SUCCESS; // csz
}

static void 
note_ntlm_auth_failure(request_rec * r)
{
    ntlm_config_rec *crec = (ntlm_config_rec *) ap_get_module_config(r->per_dir_config, &ntlm_module);
    unsigned char *line;

    line = apr_pstrdup(r->pool, NTLM_AUTH_NAME);

    apr_table_setn(r->err_headers_out, r->proxyreq ? "Proxy-Authenticate" : "WWW-Authenticate", line);
    if (crec->ntlm_basic_on) {
        line = apr_pstrcat(r->pool, "Basic realm=\"", crec->ntlm_basic_realm, "\"", NULL);
        apr_table_addn(r->err_headers_out, r->proxyreq ? "Proxy-Authenticate" : "WWW-Authenticate", line);
    }
}

static void 
log_ntlm_logon_denied(request_rec * r)
{
    log(r, APLOG_ERR, "NTLM/SMB user \"%s\": authentication failure for \"%s\"", r->user, r->uri);
}

ntlmssp_info_rec *
get_ntlm_header(request_rec * r, ntlm_config_rec * crec)
{
    const char *auth_line = apr_table_get(r->headers_in,
                                         r->proxyreq ? "Proxy-Authorization"
                                         : "Authorization");
    unsigned char *msg;
    int len, foo;
    unsigned ntlmssp_flags=0;
    ntlmssp_info_rec *ntlmssp;
	ntlm_connection_rec* ntlm_connection;

    /* fhz 16-10-01: take care of unicode strings */
	ntlm_connection = get_ntlm_connection(r->connection);
    if (ntlm_connection->ntlmssp_flags) ntlmssp_flags=ntlm_connection->ntlmssp_flags;

    if (!auth_line) {
        log(r,  APLOG_NOERRNO | APLOG_ERR, "no auth_line");
        return NULL;
    }
    if (strcmp(ap_getword_white(r->pool, &auth_line), NTLM_AUTH_NAME)) {
        log(r,  APLOG_NOERRNO | APLOG_ERR, "ap_getword_white failed");
        return NULL;
    }
    log(r, APLOG_DEBUG, "got auth_line \"%s\"",auth_line);
    msg = uudecode_binary(r->connection->pool, auth_line, &len);
    ntlmssp = apr_pcalloc(r->pool, sizeof(ntlmssp_info_rec));
    if ((foo = ntlm_decode_msg(r, ntlmssp, msg, len,&ntlmssp_flags)) != 0) {
        log(r,  APLOG_NOERRNO | APLOG_ERR, 
                      "ntlm_decode_msg failed: type: %d, host: \"%s\", "
                      "user: \"%s\", domain: \"%s\", error: %d",
                      ntlmssp->msg_type,
                      ntlmssp->host, ntlmssp->user, ntlmssp->domain,
                      foo);
        return NULL;
    }

    /* fhz 16-10-01: take care of unicode strings */
    if (ntlmssp_flags)
	    ntlm_connection->ntlmssp_flags=ntlmssp_flags;
    log(r, APLOG_DEBUG, "got header with host \"%s\", domain \"%s\", unicode flag %d",
        ntlmssp->host, ntlmssp->domain, ntlmssp_flags);
    return ntlmssp;
}

static int 
send_ntlm_challenge(request_rec * r, ntlm_config_rec * crec, int win9x)
{
    struct ntlm_msg2 msg;
    struct ntlm_msg2_win9x msg_win9x;
    unsigned char *challenge;
    unsigned int l;
	ntlm_connection_rec* ntlm_connection;

    log(r, APLOG_INFO, "received msg1 keep-alive: %d, keepalives: %d", r->connection->keepalive, r->connection->keepalives);
	ntlm_connection = get_ntlm_connection(r->connection);
	if(ntlm_connection == NULL) {
        log(r, APLOG_NOERRNO | APLOG_ERR, "ntlm_connection is NULL");
        return HTTP_INTERNAL_SERVER_ERROR;
	}
    if (ntlm_connection->handle == NULL) {
        ntlm_connection->nonce = apr_pcalloc(r->connection->pool, NONCE_LEN);
        ntlm_connection->handle = NTLM_Connect(crec->ntlm_server, crec->ntlm_backup, crec->ntlm_domain, ntlm_connection->nonce);

        if (!ntlm_connection->handle) {
        log(r, APLOG_NOERRNO | APLOG_ERR, "send_ntlm_challenge: no conn. handle...trouble communicating with PDC/BDC? returning internal server error");
            return HTTP_INTERNAL_SERVER_ERROR;
	    }
    }
    if (win9x==0) {
	    ntlm_encode_msg2(ntlm_connection->nonce, &msg);
	    challenge = uuencode_binary(r->pool, (unsigned char *) &msg, sizeof(msg));
	}
    else	{
	    l=ntlm_encode_msg2_win9x(ntlm_connection->nonce, &msg_win9x, crec->ntlm_domain,ntlm_connection->ntlmssp_flags);
	    challenge = uuencode_binary(r->pool, (unsigned char *)&msg_win9x,l);
	}

	/* This is to make sure that when receiving msg3 that the r->connection is still alive  
	 * after sending the nonce to the client
	 */
	if(r->connection->keepalives >= r->server->keep_alive_max) {
    	log(r, APLOG_INFO, "Decrement the connection request count to keep it alive");
		r->connection->keepalives -= 1;
	}

    apr_table_setn(r->err_headers_out, r->proxyreq ? "Proxy-Authenticate" : "WWW-Authenticate", apr_psprintf(r->pool, "%s %s", NTLM_AUTH_NAME, challenge));
    log(r, APLOG_INFO, "send %s \"%s %s\"",r->proxyreq ? "Proxy-Authenticate" : "WWW-Authenticate", NTLM_AUTH_NAME, challenge);

    return HTTP_UNAUTHORIZED;
}

static int 
ntlm_check_response(request_rec * r, ntlm_config_rec * crec,
                    ntlmssp_info_rec * ntlmssp)
{
	apr_status_t rv;
	ntlm_connection_rec* ntlm_connection;
    log(r, APLOG_INFO, "received msg3");

	ntlm_connection = get_ntlm_connection(r->connection);
	if(ntlm_connection == NULL) {
        log(r, APLOG_NOERRNO | APLOG_ERR, "ntlm_connection is NULL");
        return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (ntlm_connection->auth_ok && ntlm_connection->user) {
 	  /* user has already valid credentials */
 		if ((!strcmp(ntlm_connection->user, ntlmssp->user))
            && (!strcmp(ntlm_connection->domain, ntlmssp->domain))
            && (!memcmp(ntlm_connection->password, ntlmssp->nt, RESP_LEN))) {
			log(r, APLOG_INFO, "silent reauthentication");
            /* silently accept login with same credentials */
			r->user = apr_pstrdup(r->connection->pool, ntlm_connection->user);
      r->ap_auth_type = apr_pstrdup(r->connection->pool, NTLM_AUTH_NAME);
     	return OK;
		}
	}
  if (!ntlm_connection->handle) {
   	log(r, APLOG_ERR, "PDC connection already closed");
    note_ntlm_auth_failure(r);
    return HTTP_UNAUTHORIZED;
   }

  if (!*ntlmssp->user) return HTTP_BAD_REQUEST;

	ntlm_connection->user = apr_pstrdup(r->connection->pool, ntlmssp->user);
  ntlm_connection->domain = (*ntlmssp->domain) ? apr_pstrdup(r->connection->pool, ntlmssp->domain) : crec->ntlm_domain;
  ntlm_connection->password = apr_pcalloc(r->connection->pool, RESP_LEN);
  memcpy(ntlm_connection->password, ntlmssp->nt, RESP_LEN);

	// Lock it to prevent two requests sent to DC simutaneously
	rv = apr_global_mutex_lock(ntlm_lock);
	if(rv != APR_SUCCESS) {
   	log(r, APLOG_ERR, "apr_global_mutex_lock(rewrite_log_lock) failed");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
 	log(r, APLOG_INFO, "authenticating user against DC");
	if (NTLM_Auth(ntlm_connection->handle,
                  ntlm_connection->user,
                  ntlm_connection->password, 1, ntlm_connection->domain) == NTV_LOGON_ERROR) {
		log_ntlm_logon_denied(r);
		note_ntlm_auth_failure(r);
		ntlm_connection->auth_ok = 0;
		rv = apr_global_mutex_unlock(ntlm_lock);
		if(rv != APR_SUCCESS) {
			log(r, APLOG_ERR, "apr_global_mutex_unlock(un_lock) failed");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		return HTTP_UNAUTHORIZED;
  }
	ntlm_connection->auth_ok = 1;
	r->user = apr_pstrdup(r->connection->pool, ntlm_connection->user);
	r->ap_auth_type = apr_pstrdup(r->connection->pool, NTLM_AUTH_NAME);

	log(r, APLOG_INFO, "NTLM/SMB user: \"%s\\%s\": authentication OK.", ntlm_connection->domain, ntlm_connection->user);
	rv = apr_global_mutex_unlock(ntlm_lock);
	if(rv != APR_SUCCESS) {
		log(r, APLOG_ERR, "apr_global_mutex_unlock(un_lock) failed");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	return OK;
}

/* rit, 9.10.00 
*       code from mod_auth.c 
*/
static apr_table_t *groups_for_user(apr_pool_t *p, char *user, char *grpfile)
{
    ap_configfile_t *f;
    apr_table_t *grps = apr_table_make(p, 15);
    apr_pool_t *sp;
    char l[MAX_STRING_LEN];
    const char *group_name, *ll, *w;
    apr_status_t status;

    if ((status = ap_pcfg_openfile(&f, p, grpfile)) != APR_SUCCESS ) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, NULL,
                      "Could not open group file: %s", grpfile);
        return NULL;
    }

    // for apache 2.0
    // apr_pool_sub_make(&sp,p,NULL);
    //
    // for apache 2.2
    apr_pool_create_ex(&sp,p,NULL,NULL);

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        if ((l[0] == '#') || (!l[0]))
            continue;
        ll = l;
        apr_pool_clear(sp);

        group_name = ap_getword(sp, &ll, ':');

        while (ll[0]) {
            w = ap_getword_conf(sp, &ll);
            if (!strcmp(w, user)) {
                apr_table_setn(grps, apr_pstrdup(p, group_name), "in");
                break;
            }
        }
    }
    ap_cfg_closefile(f);
    apr_pool_destroy(sp);
    return grps;
}

/* SHH 2000-05-10: added the following method by copying from several
 * places (this file and apache sources).  very little is my own work.
 * *sigh*; i've become a thief on my older days. */
static int 
authenticate_basic_user(request_rec * r, ntlm_config_rec * crec,
                        const char *auth_line_after_Basic)
{
    char *sent_user, *sent_pw, *sent_domain = "", *s;

    while (*auth_line_after_Basic == ' ' || *auth_line_after_Basic == '\t')
        auth_line_after_Basic++;

    sent_user = ap_pbase64decode(r->pool, auth_line_after_Basic);
    if (sent_user != NULL) {
        if ((sent_pw = strchr(sent_user, ':')) != NULL) {
            *sent_pw = '\0';
            ++sent_pw;
        } else
            sent_pw = "";
        if ((s = strchr(sent_user, '\\')) != NULL
            || (s = strchr(sent_user, '/')) != NULL) {
            /* domain supplied as part of the user name. */
            *s = '\0';
            sent_domain = sent_user;
            sent_user = s + 1;
            /* check that we are willing to serve this domain. */
            if (strcasecmp(sent_domain, crec->ntlm_domain) != 0) {
                /* domain mismatch. */
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r,
                              "Basic/SMB user \"%s\\%s\": "
                              "authentication failure; "
                              "domain not \"%s\".",
                              sent_domain, sent_user, crec->ntlm_domain);
                return HTTP_UNAUTHORIZED;
            }
        }
    } else
        sent_user = sent_pw = "";

    if (Valid_User(sent_user, sent_pw,
                   crec->ntlm_server, crec->ntlm_backup,
                   crec->ntlm_domain) != NTV_NO_ERROR) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r,
                      "Basic/SMB user \"%s\\%s\": "
                      "authentication failure for \"%s\"",
                      sent_domain, sent_user, r->uri);
        ap_note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }
    /* Note that this allocation has to be made from
     * r->connection->pool because it has the lifetime of the
     * connection.  The other allocations are temporary and can be
     * tossed away any time. */
    r->user = apr_pstrcat(r->connection->pool, sent_user, NULL);
    r->ap_auth_type = "Basic";

    log(r, APLOG_INFO, "Basic/SMB user: \"%s\\%s\": authentication OK.",
        sent_domain, sent_user);

    return OK;
}

static int 
authenticate_ntlm_user(request_rec * r, ntlm_config_rec * crec)
{
    ntlmssp_info_rec *ntlmssp;
    int win9x=0;
	ntlm_connection_rec* ntlm_connection;
	char key[20];

    /* If this is the first request with this connection, then create
     * a ntlm_connection entry for it. It will be cleaned up when the
     * connection is dropped */
	apr_thread_mutex_lock(crec->ntlm_mutex);
	ntlm_connection = get_ntlm_connection(r->connection);
    if (ntlm_connection == NULL) {
        ntlm_connection = apr_pcalloc(r->connection->pool, sizeof(ntlm_connection_rec));
        ntlm_connection->auth_ok = 0;
        ntlm_connection->ntlmssp_flags = 0;
   		apr_pool_cleanup_register(r->connection->pool, r->connection, cleanup_ntlm_connection, apr_pool_cleanup_null);
		sprintf(key, "%u", r->connection->id);
        log(r, APLOG_INFO, "NTLMXX-Creating new ntlm_connection: %s", key);
		apr_pool_userdata_set(ntlm_connection, key, NULL, r->connection->pool);
    }
	apr_thread_mutex_unlock(crec->ntlm_mutex); 
    if ((ntlmssp = get_ntlm_header(r, crec)) == NULL) {
        note_ntlm_auth_failure(r);
        log(r, APLOG_NOERRNO | APLOG_ERR, "missing/corrupt NTLM header");
        return HTTP_UNAUTHORIZED;
    }
    switch (ntlmssp->msg_type) {
      case 1:
	 	/* Win9x: in msg1, host and domain never sent */
 	 	if ((strcmp(ntlmssp->host,"")==0) && (strcmp(ntlmssp->domain,"")==0)) win9x=1;
        return send_ntlm_challenge(r, crec,win9x);
      case 3:
        return ntlm_check_response(r, crec, ntlmssp);
    }
    log(r, APLOG_NOERRNO | APLOG_ERR, "authenticate_ntlm_user: bad request");
    return HTTP_BAD_REQUEST;
}

static int 
authenticate_user(request_rec * r)
{
    ntlm_config_rec *crec = (ntlm_config_rec *) ap_get_module_config(r->per_dir_config, &ntlm_module);
    const char *auth_line = apr_table_get(r->headers_in, r->proxyreq ? "Proxy-Authorization" : "Authorization");

    if (!crec->ntlm_on) return DECLINED;

    if (!auth_line) {
        note_ntlm_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }
    if (crec->ntlm_basic_on && strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Basic") == 0) 
        return authenticate_basic_user(r, crec, auth_line);

    return authenticate_ntlm_user(r, crec);
}

static int 
check_user_access(request_rec * r)
{
	ntlm_connection_rec* ntlm_connection;
    ntlm_config_rec *crec =
        (ntlm_config_rec *) ap_get_module_config(r->per_dir_config,
                                                 &ntlm_module);
    char *user = r->user;
    int m = r->method_number;
    int method_restricted = 0;
    register int x;
    const char *t, *w;
    apr_table_t *grpstatus; /* rit */
    apr_table_t *e = r->subprocess_env; /* rit */
    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs;
	ntlm_connection = get_ntlm_connection(r->connection);

    /* 
     * If the switch isn't on, don't bother. 
     */
    if (!crec->ntlm_on) {
        return DECLINED;
    }
    if (!reqs_arr) {
        return OK;
    }


    reqs = (require_line *) reqs_arr->elts;

    /* 
     * Did we authenticate this user?
     * If not, we don't want to do user/group checking.
     */
    if (strcmp(r->ap_auth_type, NTLM_AUTH_NAME) == 0
        && (!ntlm_connection || !ntlm_connection->auth_ok)) {
        return DECLINED;
    }
    /* rit, get groups for user */
    if (crec->ntlm_grpfile)
        grpstatus = groups_for_user(r->pool, user, crec->ntlm_grpfile);
    else
        grpstatus = NULL;

    for (x = 0; x < reqs_arr->nelts; x++) {
        if (!(reqs[x].method_mask & (1 << m)))
            continue;

        method_restricted = 1;

        t = reqs[x].requirement;
        w = ap_getword_white(r->pool, &t);
        if (!strcmp(w, "valid-user"))
            return OK;
        if (!strcmp(w, "user")) {
            while (t[0]) {
                w = ap_getword_conf(r->pool, &t);
                if (!strcmp(user, w))
                    return OK;
            }
        }
/* rit, 9.10.00: coding aus mod_auth.c */
        else if (!strcmp(w, "group")) {
            if (!grpstatus) {
                return DECLINED; /* DBM group?  Something else? */
            }
            while (t[0]) {
                w = ap_getword_conf(r->pool, &t);
                if (apr_table_get(grpstatus, w)) {
                    apr_table_setn(e, "REMOTE_NTGROUP", w);
                    return OK;
                }
            }
/* rit, finish group testng */
        } else if (crec->ntlm_authoritative) {
            /* if we aren't authoritative, any require directive could
             * be valid even if we don't grok it.  However, if we are
             * authoritative, we can warn the user they did something
             * wrong. That something could be a missing
             * "AuthAuthoritative off", but more likely is a typo in
             * the require directive. */
            log(r, APLOG_ERR,
                          "access to \"%s\" failed, reason: "
                          "unknown require directive:"
                          "\"%s\"",
                          r->uri, reqs[x].requirement);
        }
    }

    if (!method_restricted) {
        return OK;
    }
    if (!(crec->ntlm_authoritative)) {
        return DECLINED;
    }
    log(r, APLOG_ERR, 
                  "access to \"%s\" failed, reason: "
                  "user \"%s\" not allowed access.",
                  r->uri, user);

    note_ntlm_auth_failure(r);
    /* 
     * We return HTTP_UNAUTHORIZED (401) because the client may wish
     * to authenticate using a different scheme, or a different
     * username. If this works, they can be granted access. If we
     * returned HTTP_FORBIDDEN (403) then they don't get a second
     * chance.
     */
    return HTTP_UNAUTHORIZED;
}

/*
 * This function is a callback and it declares what other functions
 * should be called for request processing and configuration requests.
 * This callback function declares the Handlers for other events.
 */
static void modntlm_register_hooks (apr_pool_t *p)
{
    static const char * const cfgPost[]={ "http_core.c", NULL };

	ap_hook_post_config(initialize_module, NULL, cfgPost, APR_HOOK_MIDDLE);
    ap_hook_child_init(initialize_child, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_check_user_id(authenticate_user, NULL,NULL,APR_HOOK_MIDDLE);
	ap_hook_auth_checker(check_user_access, NULL,NULL,APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA ntlm_module = {
    STANDARD20_MODULE_STUFF,
    create_ntlm_dir_config, /* create per-directory config structures */
    NULL, /* merge per-directory config structures  */
    NULL, /* create per-server config structures    */
    NULL, /* merge per-server config structures     */
    ntlm_cmds, /* command handlers */
    modntlm_register_hooks, /* register hooks */
};
