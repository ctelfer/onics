/*
 * ONICS
 * Copyright 2016-2022
 * Christopher Adam Telfer
 *
 * prload.h -- Code loading external protocol libraries
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
#ifndef __prload_h
#define __prload_h

#include "prid.h"
#include "protoparse.h"
#include "ns.h"

/* Called by application */

void load_external_protocols(void);

void unload_external_protocols(void);


/*
 * Called by protocol libraries to register/unregister protocols
 *
 * Library must have the following externally visible functions:
 *
 *   int load(void);
 *   void unload(void);
 * 
 */

struct oproto {
	uint prid;
	struct proto_parser_ops *ops;
	struct ns_namespace *ns;
	ushort etype;
};

int register_protocol(struct oproto *opr);

void unregister_protocol(struct oproto *opr);

#endif /* __prload_h */
