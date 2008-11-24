/*
 * $Id: mod_ntlm.h,v 1.3.4.1 2003/02/23 15:56:26 casz Exp $
 *
 */

/* Preprocessor macro definitions */
#define NTLM_PACKAGE_NAME "NTLM"
#define NTLM_AUTH_NAME "NTLM"

/* Header inclusions */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "apr_base64.h"
#include "apr_strings.h"
#include "http_protocol.h"

#include "http_request.h"

/*
#include "httpd.h"
#include "http_config.h"
#include "apr_general.h"
*/

#include "smbval/valid.h"

#ifndef DEFAULT_MODNTLM_STRING
#define DEFAULT_MODNTLM_STRING "apache2_mod_ntlm: A request was made."
#endif

module AP_MODULE_DECLARE_DATA ntlm_module;

typedef struct ntlm_config_struct {
    unsigned int ntlm_on;
    unsigned int ntlm_basic_on;
    char *ntlm_basic_realm;
    unsigned int ntlm_authoritative;
    char *ntlm_domain;
    char *ntlm_server;
    char *ntlm_backup;
    char *ntlm_grpfile;
	char *ntlm_lockfile;
	apr_thread_mutex_t *ntlm_mutex;  /* Protect ntlm_connection variable   */
} ntlm_config_rec;

typedef struct ntlm_connection_struct {
    void *handle;
    char *nonce;
    char *user;
    char *domain;
    char *password;
    int auth_ok;
    unsigned int ntlmssp_flags;
} ntlm_connection_rec;
