#include "dat.h"
#include <httpd.h>


enum {
	Httpget,
	Httppost,
};


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

int
hspairsfmt(Fmt *f)
{
	HSPairs *sp;

	for(sp = va_arg(f->args, HSPairs*); sp != nil; sp = sp->next){
		fmtprint(fmt, "%U=%U", sp->s, sp->t);
		if(sp->next != nil)
			fmtprint(fmt, "&");
	}
}

static char*
readall(int fd)
{
	char buf[1024], *s;
	int n, tot;

	s = nil;
	for(tot = 0; (n = read(f, buf, (long)sizeof buf)) > 0; tot += n){
		s = erealloc(s, tot + n + 1);
		memcpy(s + tot, buf, n);
	}
	if(n < 0){
		free(s);
		werrstr("read: %r");
		return nil;
	}

	s[tot] = '\0';
	return s;
}

static char*
dohttp(int meth, char *url, HSPairs* sp)
{
	char buf[1024], *mtpt, *s;
	int ctlfd, fd, conn, n;

	ctlfd = -1;
	fd = -1;
	mtpt = "/mnt/web";
	snprint(buf, sizeof buf, "%s/clone", mtpt);
	if((ctlfd = open(buf, ORDWR)) < 0){
		werrstr("couldn't open %s: %r", buf);
		return nil;
	}
	if((n = read(ctlfd, buf, sizeof buf-1)) < 0){
		werrstr("reading clone: %r");
		goto out;
	}
	if(n == 0){
		werrstr("short read on clone");
		goto out;
	}
	buf[n] = '\0';
	conn = atoi(buf);

	switch(meth){
		case Httpget:
			if(fprint(ctlfd, "url %s?%P", url, sp) < 0){
				werrstr("url ctl write: %r");
				goto out;
			}
			break;
		case Httppost:
			snprint(buf, sizeof buf, "%s/%d/postbody", mtpt, conn);
			if((fd = open(buf, OWRITE)) < 0){
				werrstr("open %s: %r", buf);
				goto out;
			}
			if(fprint(fd, "%P", sp) < 0){
				werrstr("post write failed: %r");
				goto out;
			}
			close(fd);
			break;
	}

	snprint(buf, sizeof buf, "%s/%d/body", mtpt, conn);
	if((fd = open(buf, OREAD)) < 0){
		werrstr("open %s: %r", buf);
		goto out;
	}

	s = readall(fd);

	if(s == nil){
		werrstr("readall: %r");
		goto out;
	}

	out:
	if(ctlfd >= 0)
		close(ctlfd);
	if(fd >= 0)
		close(fd);
	return s;
}

int
refresh(Key *k) {
	char *issuer, *clientid, *clientsecret, *refreshtoken;


	if((issuer = _strfindattr(k->attr, "issuer")) == nil){
		werrstr("issuer missing");
		return -1;
	}
	if((clientid = _strfindattr(k->attr, "clientid")) == nil){
		werrstr("clientid missing");
		return -1;
	}
	if((clientsecret = _strfindattr(k->attr, "clientsecret")) == nil){
		werrstr("clientsecret missing");
		return -1;
	}
	refreshtoken = _strfindattr(k->privattr, "!refreshtoken");
	if(refreshtoken == nil)
		return 0;
	// todo
	return 0;
}


static int
oauthinit(Proto *p, Fsstate *fss)
{
	int ret;
	Key *k;
	Keyinfo ki;
	State *s;

	fmtinstall('U', hurlfmt);
	fmtinstall('P', hspairsfmt);
	ret = findkey(&k, mkkeyinfo(&ki, fss, nil), "%s", p->keyprompt);
	if(ret != RpcOk)
		return ret;
	refresh(k);
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
	char buf[500];
	char *accesstoken;
	State *s;

	s = fss->ps;
	switch(fss->phase){
	default:
		return phaseerror(fss, "read");

	case HaveToken:
		accesstoken = _strfindattr(s->key->privattr, "!accesstoken");
		if(accesstoken == nil)
			return failure(fss, "oauthread cannot happen");
		snprint(buf, sizeof buf, "%q", accesstoken);
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

Proto pass =
{
.name=		"oauth",
.init=		oauthinit,
.write=		oauthwrite,
.read=		oauthread,
.close=		oauthclose,
.addkey=		replacekey,
.keyprompt=	"issuer? clientid? !clientsecret? !accesstoken? !refreshtoken?",
};
