/* mod_ntlm file: $Id: std-defines.h,v 1.3 2003/02/21 01:55:14 casz Exp $ */

#ifndef STD_DEFINES_H
#define STD_DEFINES_H

/* RFCNB Standard includes ... */
/* 
 * 
 * SMBlib Standard Includes
 * 
 * Copyright (C) 1996, Richard Sharpe
 * 
 */
/* One day we will conditionalize these on OS types ... */

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

#ifndef BOOL
#define BOOL int
#endif
typedef short int16;

#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#if 0
#include <strings.h>
#endif

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#endif
