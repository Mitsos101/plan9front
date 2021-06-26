#include "dat.h"
#include <httpd.h>
#include <json.h>

#define nelem(x) ((sizeof(x))/(sizeof(x[0]))

static char* k1[] = {"client_id", "!client_secret", "!refresh_token"};
static char* k2[] = {"!access_token", "!id_token", "!refresh_token", "scope", "token_type"};

enum {
	Httpget,
	Httppost,
};

typedef struct Pair Pair;
struct Pair
{
	char *s;
	char *t;
};

typedef struct PArray PArray;
struct PArray
{
	int n;
	Pair *p;
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
parrayfmt(Fmt *f)
{
	PArray *pa;
	int i;

	pa = va_args(f->args, PArray*);
	if(pa == nil)
		return 0;
	for(i = 0; i < pa.n; i++){
		if(i != 0) fmtprint(f, "&");
		fmtprint(f, "%P", pa.p[i]);
	}

	return 0;
}

int
pairfmt(Fmt *f)
{
	Pair *p;

	fmtprint(f, "%U=%U", p.s, p.t);

	return 0;
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
dohttp(int meth, char *url, PArray *pa)
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
			if(fprint(ctlfd, "url %s?%A", url, pa) < 0){
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
			if(fprint(fd, "%A", pa) < 0){
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

	if((s = readall(fd)) == nil){
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

JSON*
jsonhttp(int meth, char *url, PArray *pa){
	char *resp;
	JSON *j;

	if((resp = dohttp(meth, url, pa)) == nil){
		werrstr("dohttp: %r");
		return nil;
	}

	if((j = jsonparse(resp)) == nil){
		werrstr("jsonparse: %r");
		return nil;
	}

	return j;
}

static int
sendkey(Key *k)
{
	int fd, rv;
	char buf[16384];

	fd = open("/mnt/factotum/ctl", ORDWR);
	if(fd < 0)
		sysfatal("opening /mnt/factotum/ctl: %r");
	rv = fprint(fd, "key %A %A\n", k->attr, k->privattr);
	read(fd, buf, sizeof buf);
	close(fd);
	return rv;
}

int
refresh(Key *k) {
	char buf[1024], *issuer, *te, *s;
	long exptime;
	Pair p[4];
	PArray pa;
	JSON *j, *t;
	Attr *a;
	int i;

	if((s = _strfindattr(k->attr, "exptime")) != nil && atol(s) >= time(0))
		return 0;

	if((issuer = _strfindattr(k->attr, "issuer")) == nil){
		werrstr("issuer missing");
		return -1;
	}
	snprint(buf, sizeof buf, "%s%s", issuer, "/.well-known/openid-configuration");

	if((j = jsonhttp(Httpget, buf, nil)) == nil){
		werrstr("jsonhttp: %r");
		return -1;
	}
	if((t = jsonbyname(j, "token_endpoint")) == nil){
		werrstr("jsonbyname: %r");
		jsonfree(j);
		return -1;
	}
	if(t->t != JSONString){
		werrstr("token endpoint is not a string");
		jsonfree(j);
		return -1;
	}
	if((te = strdup(t->s)) == nil){
		werrstr("strdup: %r");
		jsonfree(j);
		return -1;
	}
	jsonfree(j);

	pa.n = 4;
	pa.a = p;
	p[3] = (Pair){"grant_type", "refresh_token"};
	for(i = 0; i < nelem(k1); i++){
		s = k1[i];
		if(s[0] == '!'){
			a = k->privattr;
			p[i].s = s + 1;
		} else {
			a = k->attr;
			p[i].s = s;
		}
		if((p[i].t = _strfindattr(a, s)) == nil){
			werrstr("%s not found", s);
			free(te);
			return -1;
		}
	}

	if((j = jsonhttp(Httppost, te, &pa)) == nil){
		werrstr("jsonhttp: %r");
		free(te);
		return -1;
	}
	free(te);

	for(i = 0; i < nelem(k2); i++){
		s = k2[i];
		if(s[0] == '!'){
			a = k->privattr;
			t = jsonbyname(j, s + 1);
		} else {
			a = k->attr;
			t = jsonbyname(j, s);
		}
		if(t != nil && t->t != JSONString){
			werrstr("%s is not a string", s);
			jsonfree(j);
			return -1;
		}
		/* todo: set attribute s in a to t->s */
	}

	t = jsonbyname(j, "expires_in");
	if(t != nil && t->t == JSONNumber){
		exptime = time(0) + (long)t->n;
		/* todo: copy exptime to k->attr */
	}

	jsonfree(j);
	if(sendkey(k) < 0){
		werrstr("sendkey: %r");
		return -1;
	}
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
	fmtinstall('P', pairfmt);
	fmtinstall('A', parrayfmt);
	ret = findkey(&k, mkkeyinfo(&ki, fss, nil), "%s", p->keyprompt);
	if(ret != RpcOk)
		return ret;
	if(refresh(k) < 0){
		return failure(fss, "refresh: %r");
	}
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
		accesstoken = _strfindattr(s->key->privattr, "!access_token");
		idtoken = _strfindattr(s->key->privattr, "!id_token");
		if(accesstoken == nil && idtoken == nil)
			return failure(fss, "oauthread cannot happen");
		if(accesstoken == nil)
			snprint(buf, sizeof buf, "id_token=%q", idtoken);
		if(idtoken == nil)
			snprint(buf, sizeof buf, "access_token=%q", accesstoken);
		if(accesstoken != nil && idtoken != nil)
			snprint(buf, sizeof buf, "id_token=%q access_token=%q", idtoken, accesstoken);
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
