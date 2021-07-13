#include <u.h>
#include <libc.h>
#include <auth.h>
#include "authlocal.h"

enum {
	ARgiveup = 100,
};

static int
dorpc(AuthRpc *rpc, char *verb, char *val, int len, AuthGetkey *getkey)
{
	int ret;

	for(;;){
		if((ret = auth_rpc(rpc, verb, val, len)) != ARneedkey && ret != ARbadkey)
			return ret;
		if(getkey == nil)
			return ARgiveup;	/* don't know how */
		if((*getkey)(rpc->arg) < 0)
			return ARgiveup;	/* user punted */
	}
}

OAuth*
auth_getoauth(AuthGetkey *getkey, char *fmt, ...)
{
	AuthRpc *rpc;
	char *p, *params;
	int fd;
	va_list arg;
	OAuth *o;

	o = nil;
	params = nil;

	fd = open("/mnt/factotum/rpc", ORDWR|OCEXEC);
	if(fd < 0)
		return nil;
	rpc = auth_allocrpc(fd);
	if(rpc == nil)
		goto out;
	quotefmtinstall();	/* just in case */
	va_start(arg, fmt);
	params = vsmprint(fmt, arg);
	va_end(arg);
	if(params == nil)
		goto out;

	if(dorpc(rpc, "start", params, strlen(params), getkey) != ARok
	|| dorpc(rpc, "read", nil, 0, getkey) != ARok)
		goto out;

	rpc->arg[rpc->narg] = '\0';
	o = malloc(sizeof(*o)+rpc->narg+1);
	if(o == nil)
		goto out;
	p = (char*)&o[1];
	strcpy(p, rpc->arg);
	o->access_token = p;

out:
	free(params);
	close(fd);
	auth_freerpc(rpc);
	return o;
}
