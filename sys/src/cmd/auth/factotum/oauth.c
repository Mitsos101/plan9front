#include "dat.h"

/* webfs and factotum need to be in the same namespace */
static int
bindwebfs(void)
{
	int srvfd;

	if(access("/mnt/web", AEXIST) < 0){
		if((srvfd = open("#s/web", ORDWR)) >= 0){
			if(mount(srvfd, -1, "/mnt", MBEFORE, "") != -1)
				return 0;
			close(srvfd);
		}
		return -1;
	}
	return 0;
}


typedef struct State State;
struct State
{
	Key *key;
};

enum
{
	HaveToken,
	Maxphase,
};

static char *phasenames[Maxphase] =
{
[HaveToken]	"HaveToken",
};

static int
oauthinit(Proto *p, Fsstate *fss)
{
	int ret;
	Key *k;
	Keyinfo ki;
	State *s;

	ret = findkey(&k, mkkeyinfo(&ki, fss, nil), "%s", p->keyprompt);
	if(ret != RpcOk)
		return ret;
	setattrs(fss->attr, k->attr);
	s = emalloc(sizeof(*s));
	s->key = k;
	fss->ps = s;
	fss->phase = HaveToken;
	return RpcOk;
}

static void
oauthclose(Fsstate *fss)
{
	State *s;

	s = fss->ps;
	if(s->key)
		closekey(s->key);
	free(s);
}

static int
oauthread(Fsstate *fss, void *va, uint *n)
{
	int m;
	char buf[2048];
	char *access_token;
	State *s;

	s = fss->ps;
	switch(fss->phase){
	default:
		return phaseerror(fss, "read");

	case HaveToken:
		access_token = _strfindattr(s->key->privattr, "!access_token");
		if(access_token == nil)
			return failure(fss, "oauthread cannot happen");
		snprint(buf, sizeof buf, "%q", access_token);
		m = strlen(buf);
		if(m > *n)
			return toosmall(fss, m);
		*n = m;
		memmove(va, buf, m);
		return RpcOk;
	}
}

static int
oauthwrite(Fsstate *fss, void*, uint)
{
	return phaseerror(fss, "write");
}

Proto oauth =
{
.name=		"oauth",
.init=		oauthinit,
.write=		oauthwrite,
.read=		oauthread,
.close=		oauthclose,
.addkey=		replacekey,
.keyprompt=	"issuer? scope? client_id? !refresh_token?",
};
