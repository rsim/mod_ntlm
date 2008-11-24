/* mod_ntlm file: $Id: std-includes.h,v 1.3 2003/02/21 01:55:14 casz Exp $ */

#ifndef STD_INCLUDES_H
#define STD_INCLUDES_H

/* RFCNB Standard includes ... */
/* 
 * 
 * RFCNB Standard Includes
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

#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/* Pick up define for INADDR_NONE */

#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif

#endif
