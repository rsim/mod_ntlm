/* mod_ntlm file: $Id: smblib.inc.c,v 1.2 2003/02/21 01:55:14 casz Exp $ */

/* UNIX SMBlib NetBIOS implementation
 * 
 * Version 1.0 SMBlib Routines
 * 
 * Copyright (C) Richard Sharpe 1996
 * 
 */

/* 
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  This program is distributed in the hope
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.  You
 * should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 675 Mass Ave, Cambridge, MA 02139, USA. */
#include <stdio.h>
#include <malloc.h>

int SMBlib_errno;
int SMBlib_SMB_Error;
#define SMBLIB_ERRNO
#define uchar unsigned char
#include "smblib-priv.h"

#include "rfcnb.h"
#include "http_log.h"

#include <signal.h>

SMB_State_Types SMBlib_State;

/* Initialize the SMBlib package     */
static int 
SMB_Init()
{
    SMBlib_State = SMB_State_Started;
    signal(SIGPIPE, SIG_IGN);   /* Ignore these ... */

/* If SMBLIB_Instrument is defines, turn on the instrumentation stuff */
#ifdef SMBLIB_INSTRUMENT
    SMBlib_Instrument_Init();
#endif

    return 0;
}

/* SMB_Connect_Server: Connect to a server, but don't negotiate protocol */
/* or anything else ...                                                  */
static SMB_Handle_Type 
SMB_Connect_Server(SMB_Handle_Type Con_Handle,
                   char *server, char *NTdomain)
{
    SMB_Handle_Type con;
    char called[80], calling[80], *address;
    int i;

#ifdef LOG
    slog(APLOG_INFO,"SMB_Connect_Server: server - %s, domain - %s ", server, NTdomain);
#endif
    /* Get a connection structure if one does not exist */
    con = Con_Handle;
    if (Con_Handle == NULL) {
        if ((con = (struct SMB_Connect_Def *) malloc(
                                   sizeof(struct SMB_Connect_Def))) == NULL) {
            SMBlib_errno = SMBlibE_NoSpace;
            return NULL;
        }
    }
    /* Init some things ... */

    strcpy(con->service, "");
    strcpy(con->username, "");
    strcpy(con->password, "");
    strcpy(con->sock_options, "");
    strcpy(con->address, "");
    strcpy(con->desthost, server);
    strcpy(con->PDomain, NTdomain);
    strcpy(con->OSName, SMBLIB_DEFAULT_OSNAME);
    strcpy(con->LMType, SMBLIB_DEFAULT_LMTYPE);
    con->first_tree = con->last_tree = NULL;

    SMB_Get_My_Name(con->myname, sizeof(con->myname));

#ifdef LOG
    slog(APLOG_INFO,"SMB_Connect_Server: my name - %s", con->myname);
#endif
    con->port = 0;              /* No port selected */

    /* Get some things we need for the SMB Header */
    con->pid = getpid();
    con->mid = con->pid;        /* This will do for now ... */
    con->uid = 0;               /* Until we have done a logon, no uid ... */
    con->gid = getgid();

    /* Now connect to the remote end, but first upper case the name of
     * the service we are going to call, sine some servers want it in
     * uppercase */
    for (i = 0; i < strlen(server); i++) {
				if( server[i] == '.') break;  /* Only copy the NetBios Name, first part before . */
        called[i] = toupper(server[i]);
		}

    called[i] = 0; /* Make it a string */

    for (i = 0; i < strlen(con->myname); i++)
        calling[i] = toupper(con->myname[i]);

    calling[strlen(con->myname)] = 0;   /* Make it a string */

    if (strcmp(con->address, "") == 0)
        address = con->desthost;
    else
        address = con->address;

#ifdef LOG
    slog(APLOG_DEBUG,"SMB_Connect_Server: address - %s", address);
#endif

    con->Trans_Connect = RFCNB_Call(called,
                                    calling,
                                    address,    /* Protocol specific */
                                    con->port);
#ifdef LOG
    slog(APLOG_DEBUG,"SMB_Connect_Server: after RFCNB_Call con->Trans_Connect = %d",  con->Trans_Connect != NULL ? 1 : 0 );
#endif

    /* Did we get one? */
    if (con->Trans_Connect == NULL) {
        if (Con_Handle == NULL) {
            Con_Handle = NULL;
            free(con);
        }
        SMBlib_errno = -SMBlibE_CallFailed;
        return NULL;
    }
    return (con);
}

/* Logon to the server. That is, do a session setup if we can. We do
 * not do Unicode yet! */
static int 
SMB_Logon_Server(SMB_Handle_Type Con_Handle, char *UserName,
                 char *PassWord, int precrypted, char* domain)
{
    struct RFCNB_Pkt *pkt;
    int param_len, pkt_len, pass_len;
    char *p, pword[128];
		char* pdomain;

		if(domain && domain[0] )
						pdomain = domain;
		else
						pdomain = Con_Handle->PDomain;

    /* First we need a packet etc ... but we need to know what
     * protocol has been negotiated to figure out if we can do it and
     * what SMB format to use ... */
    if (Con_Handle->protocol < SMB_P_LanMan1) {
#ifdef LOG
    slog(APLOG_ERR,"SMB_Logon_Server: bad protocol");
#endif
        SMBlib_errno = SMBlibE_ProtLow;
        return (SMBlibE_BAD);
    }
    if (precrypted) {
        pass_len = 24;
        memcpy(pword, PassWord, 24);
    } else {
        strcpy(pword, PassWord);
        if (Con_Handle->encrypt_passwords) {
            pass_len = 24;
            SMBencrypt((uchar *) PassWord,
                       (uchar *) Con_Handle->Encrypt_Key, (uchar *) pword);
        } else
            pass_len = strlen(pword);
    }

    /* Now build the correct structure */
    if (Con_Handle->protocol < SMB_P_NT1) {
#ifdef LOG
    slog(APLOG_INFO,"SMB_Logon_Server: type is LM (%d)", Con_Handle->protocol);
#endif
        param_len = strlen(UserName) + 1 + pass_len + 1 +
            strlen(pdomain) + 1 +
            strlen(Con_Handle->OSName) + 1;

        pkt_len = SMB_ssetpLM_len + param_len;

        pkt = (struct RFCNB_Pkt *) RFCNB_Alloc_Pkt(pkt_len);

        if (pkt == NULL) {
#ifdef LOG
    slog(APLOG_ERR,"SMB_Logon_Server: pkt == NULL");
#endif
            SMBlib_errno = SMBlibE_NoSpace;
            return (SMBlibE_BAD);       /* Should handle the error */
        }
        bzero(SMB_Hdr(pkt), SMB_ssetpLM_len);
        SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);   /* Plunk
                                                                 * in IDF */
        *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBsesssetupX;
        SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, Con_Handle->pid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, Con_Handle->mid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, Con_Handle->uid);
        *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 10;
        *(SMB_Hdr(pkt) + SMB_hdr_axc_offset) = 0xFF;    /* No extra
                                                         * command */
        SSVAL(SMB_Hdr(pkt), SMB_hdr_axo_offset, 0);

        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_mbs_offset, SMBLIB_MAX_XMIT);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_mmc_offset, 2);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_vcn_offset, Con_Handle->pid);
        SIVAL(SMB_Hdr(pkt), SMB_ssetpLM_snk_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_pwl_offset, pass_len + 1);
        SIVAL(SMB_Hdr(pkt), SMB_ssetpLM_res_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpLM_bcc_offset, param_len);

        /* Now copy the param strings in with the right stuff */
        p = (char *) (SMB_Hdr(pkt) + SMB_ssetpLM_buf_offset);

        /* Copy in password, then the rest. Password has a null at end */
        memcpy(p, pword, pass_len);

        p = p + pass_len + 1;

        strcpy(p, UserName);
        p = p + strlen(UserName);
        *p = 0;

        p = p + 1;

        strcpy(p, pdomain);
        p = p + strlen(pdomain);
        *p = 0;
        p = p + 1;

        strcpy(p, Con_Handle->OSName);
        p = p + strlen(Con_Handle->OSName);
        *p = 0;
    } else {
#ifdef LOG
    slog(APLOG_INFO,"SMB_Logon_Server: type is NTLM (%d)", Con_Handle->protocol);
#endif
        /* We don't admit to UNICODE support ... */
        param_len = strlen(UserName) + 1 + pass_len +
            strlen(pdomain) + 1 +
            strlen(Con_Handle->OSName) + 1 +
            strlen(Con_Handle->LMType) + 1;

        pkt_len = SMB_ssetpNTLM_len + param_len;

        pkt = (struct RFCNB_Pkt *) RFCNB_Alloc_Pkt(pkt_len);

        if (pkt == NULL) {
#ifdef LOG
    slog(APLOG_ERR,"SMB_Logon_Server: pkt == NULL, second check");
#endif
            SMBlib_errno = SMBlibE_NoSpace;
            return (-1);        /* Should handle the error */
        }
        bzero(SMB_Hdr(pkt), SMB_ssetpNTLM_len);
        SIVAL(SMB_Hdr(pkt), SMB_hdr_idf_offset, SMB_DEF_IDF);   /* Plunk
                                                                 * in IDF */
        *(SMB_Hdr(pkt) + SMB_hdr_com_offset) = SMBsesssetupX;
        SSVAL(SMB_Hdr(pkt), SMB_hdr_pid_offset, Con_Handle->pid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_tid_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_mid_offset, Con_Handle->mid);
        SSVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset, Con_Handle->uid);
        *(SMB_Hdr(pkt) + SMB_hdr_wct_offset) = 13;
        *(SMB_Hdr(pkt) + SMB_hdr_axc_offset) = 0xFF;    /* No extra
                                                         * command */
        SSVAL(SMB_Hdr(pkt), SMB_hdr_axo_offset, 0);

        SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_mbs_offset, SMBLIB_MAX_XMIT);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_mmc_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_vcn_offset, 0);
        SIVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_snk_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_cipl_offset, pass_len);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_cspl_offset, 0);
        SIVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_res_offset, 0);
        SIVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_cap_offset, 0);
        SSVAL(SMB_Hdr(pkt), SMB_ssetpNTLM_bcc_offset, param_len);

        /* Now copy the param strings in with the right stuff */
        p = (char *) (SMB_Hdr(pkt) + SMB_ssetpNTLM_buf_offset);

        /* Copy  in password, then the rest. Password has no null at end */
        memcpy(p, pword, pass_len);

        p = p + pass_len;

        strcpy(p, UserName);
        p = p + strlen(UserName);
        *p = 0;

        p = p + 1;

        strcpy(p, pdomain);
        p = p + strlen(pdomain);
        *p = 0;
        p = p + 1;

        strcpy(p, Con_Handle->OSName);
        p = p + strlen(Con_Handle->OSName);
        *p = 0;
        p = p + 1;

        strcpy(p, Con_Handle->LMType);
        p = p + strlen(Con_Handle->LMType);
        *p = 0;
    }

    /* Now send it and get a response */
    if (RFCNB_Send(Con_Handle->Trans_Connect, pkt, pkt_len) < 0) {
#ifdef LOG
    slog(APLOG_ERR,"SMB_Logon_Server: Error sending SessSetupX request");
#endif
#ifdef SMB_DEBUG
        fprintf(stderr, "Error sending SessSetupX request\n");
#endif
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_SendFailed;
        return (SMBlibE_BAD);
    }

    /* Now get the response ... */
    if (RFCNB_Recv(Con_Handle->Trans_Connect, pkt, pkt_len) < 0) {
#ifdef LOG
    slog(APLOG_ERR,"SMB_Logon_Server: Error receiving response to SessSetupAndX");
#endif
#ifdef SMB_DEBUG
        fprintf(stderr, "Error receiving response to SessSetupAndX\n");
#endif
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_RecvFailed;
        return (SMBlibE_BAD);
    }
    /* Check out the response type ... */

    if (CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset) != SMBC_SUCCESS) {
        /* Process error */
#ifdef LOG
    slog(APLOG_ERR,"SMB_Logon_Server: SMB_SessSetupAndX failed; errorclass = %i, Error Code = %i\n",
         CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
         SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif
#ifdef SMB_DEBUG
        fprintf(stderr,
                "SMB_SessSetupAndX failed; errorclass = %i, Error Code = %i\n",
                CVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset),
                SVAL(SMB_Hdr(pkt), SMB_hdr_err_offset));
#endif
        SMBlib_SMB_Error = IVAL(SMB_Hdr(pkt), SMB_hdr_rcls_offset);
        RFCNB_Free_Pkt(pkt);
        SMBlib_errno = SMBlibE_Remote;
        return (SMBlibE_BAD);
    }
/** @@@ mdz: check for guest login { **/
    if (SVAL(SMB_Hdr(pkt), SMB_ssetpr_act_offset) & 0x1) {
        /* do we allow guest login? NO! */
#ifdef LOG
    slog(APLOG_ERR,"SMB_Logon_Server: no guest login");
#endif
        return (SMBlibE_BAD);
    }
/** @@@ mdz: } **/

#ifdef SMB_DEBUG
    fprintf(stderr, "SessSetupAndX response. Action = %i\n",
            SVAL(SMB_Hdr(pkt), SMB_ssetpr_act_offset));
#endif

    /* Now pick up the UID for future reference ... */
    Con_Handle->uid = SVAL(SMB_Hdr(pkt), SMB_hdr_uid_offset);
    RFCNB_Free_Pkt(pkt);

#ifdef LOG
    slog(APLOG_INFO,"SMB_Logon_Server: login OK");
#endif
    return 0;
}

/* Disconnect from the server, and disconnect all tree connects */
static int 
SMB_Discon(SMB_Handle_Type Con_Handle, BOOL KeepHandle)
{
#ifdef LOG
    slog(APLOG_INFO,"SMB_Discon");
#endif
    /* We just disconnect the connection for now ... */
    RFCNB_Hangup(Con_Handle->Trans_Connect);

    if (!KeepHandle)
        free(Con_Handle);

    return 0;
}
