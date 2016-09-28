/*
 * ONICS
 * Copyright 2016
 * Christopher Adam Telfer
 *
 * prlib.h -- Code for creating external protocol libraries
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
#ifndef __prlib_h
#define __prlib_h

#include "prid.h"
#include "protoparse.h"
#include "ns.h"

struct prlib {
	const char *name;
	uint prid;
	ushort etype;
	struct proto_parser_ops *pp_ops;
	struct ns_namespace *ns;
};

#define BEGIN_EXTERN_PRLIBS_DECL \
struct prlib _prlibs[] = {

#define PROTO(_n, _id, _ops, _ns) \
	{ (_n), (_id), 0, &(_ops), &(_ns) },

#define ETHPROTO(_n, _id, _et, _ops, _ns) \
	{ (_n), (_id), (_et), &(_ops), &(_ns) },

#define END_EXTERN_PRLIBS_DECL \
	{ NULL, PRID_NONE, 0, NULL, NULL } \
};

#endif /*__prlib_h */
