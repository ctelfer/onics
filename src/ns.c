#include "ns.h"
#include "protoparse.h"
#include <string.h>
#include <stdlib.h>

static struct ns_elem *rootelem[256] = { 0 };
static struct ns_namespace rootns =
	NS_NAMESPACE_I("", NULL, PPT_NONE, rootelem);

#define TYPEOK(t) ((t) >= NST_NAMESPACE && (t) <= NST_MASKSTR)


int ns_add_elem(struct ns_namespace *ns, struct ns_elem *e)
{
	int id;
	int freeid = -1;
	struct ns_elem *e2;

	abort_unless(e && TYPEOK(e->type));

	if (ns == NULL)
		ns = &rootns;

	freeid = -1;
	for (id = 0; id < ns->nelem; ++id) {
		e2 = ns->elems[id];
		if (e2 == NULL) {
			if (freeid < 0)
				freeid = id;
			continue;
		}
		if (e2->name == NULL)
			continue;
		if (strcmp(e2->name, e->name) == 0)
			return -1;
	}

	if (freeid == -1)
		return -1;

	e->parent = ns;
	ns->elems[freeid] = e;

	return 0;
}


void ns_rem_elem(struct ns_elem *e)
{
	struct ns_namespace *ns;
	int id;

	abort_unless(e && TYPEOK(e->type));

	ns = e->parent;
	if (ns != NULL) {
		abort_unless(ns->type == NST_NAMESPACE);
		abort_unless(ns->elems != NULL);

		for (id = 0; id < ns->nelem; ++id)
			if (ns->elems[id] == e)
				break;

		abort_unless(id < ns->nelem);
		ns->elems[id] = NULL;
		e->parent = NULL;
	}
}


struct ns_elem *ns_lookup(struct ns_namespace *ns, const char *name)
{
	struct ns_elem *elem = NULL;
	const char *p, *e;
	int i;

	abort_unless(name);

	p = name;
	if (!ns)
		ns = &rootns;

	while (*p != '\0') {
		for (e = p; *e != '\0' && *e != '.'; ++e) ;

		for (i = 0; i < ns->nelem; ++i) {
			elem = ns->elems[i];
			if (elem == NULL || elem->name == NULL)
				continue;
			if ((strncmp(elem->name, p, e - p) == 0) && 
			    (*(elem->name + (e - p)) == '\0'))
				break;
		}

		if (i == ns->nelem)
			return NULL;

		if (*e != '\0') {
			if (elem->type != NST_NAMESPACE)
				return NULL;
			ns = (struct ns_namespace *)elem;
			p = e + 1;
		}
		else {
			p = e;
		}
	}


	return elem;
}


