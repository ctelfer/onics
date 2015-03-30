/*
 * ONICS
 * Copyright 2012-2015
 * Christopher Adam Telfer
 *
 * sysdeps.h -- system dependencies for ONICS.
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __sysdeps_h
#define __sysdeps_h

#include "onics_config.h"

/* use this for ANSI-C 89 compilers */
/* #define ONICS_INLINE  */
/* #define ONICS_PACK_DECL( __DECL__ ) */

/* use this for gcc & clang */
#define ONICS_INLINE inline
#define ONICS_PACK_DECL( __DECL__ ) \
	__DECL__ __attribute__((packed))

#endif /* __sysdeps_h */
