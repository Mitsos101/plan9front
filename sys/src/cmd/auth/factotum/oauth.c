#include "dat.h"
#include <httpd.h>
#include <json.h>

typedef struct Grant Grant;
struct Grant
{
	char *type;
	char *attr;
};

static Grant grants[] = {
							{"urn:ietf:params:oauth:grant-type:device_code", "device_code"},
							{"refresh_token", "!refresh_token"},
						};
static char* cattrs[] = {"client_id", "!client_secret"};
static char* jattrs[] = {"!access_token", "!id_token", "!refresh_token", "scope", "token_type"};

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

#pragma varargck	type	"P"	Pair*
#pragma varargck	type	"L"	PArray*

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
parrayfmt(Fmt *f)
{
	PArray *pa;
	int i;

	pa = va_arg(f->args, PArray*);
	if(pa == nil)
		return 0;
	for(i = 0; i < pa->n; i++){
		if(i != 0) fmtprint(f, "&");
		fmtprint(f, "%P", &pa->p[i]);
	}

	return 0;
}

static int
pairfmt(Fmt *f)
{
	Pair *p;

	p = va_arg(f->args, Pair*);
	fmtprint(f, "%U=%U", p->s, p->t);

	return 0;
}

static char*
readall(int fd)
{
	char buf[1024], *s;
	int n, tot;

	s = nil;
	for(tot = 0; (n = read(fd, buf, (long)sizeof buf)) > 0; tot += n){
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

	s = nil;
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
			if(fprint(ctlfd, "url %s?%L", url, pa) < 0){
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
			if(fprint(fd, "%L", pa) < 0){
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

static JSON*
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
refresh(Key *k) {
	char buf[1024], *issuer, *te, *s;
	long exptime;
	Pair p[nelem(cattrs) + 2];
	PArray pa;
	JSON *j, *t;
	Attr *a, *b;
	Grant *g;
	int i;

	if((s = _strfindattr(k->attr, "exptime")) != nil && atol(s) >= time(0))
		return 0;

	if((issuer = _strfindattr(k->attr, "issuer")) == nil){
		werrstr("issuer missing");
		return -1;
	}
	snprint(buf, sizeof buf, "%s%s", issuer, "/.well-known/openid-configuration");

	if((te = _strfindattr(k->attr, "token_endpoint")) != nil)
		te = strdup(te);
	else{
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
	}

	for(i = 0; i < nelem(grants); i++){
		s = grants[i].attr;
		a = s[0] == '!' ? k->privattr : k->attr;
		if(_strfindattr(a, s) != nil)
			break;
	}

	if(i == nelem(grants)){
		werrstr("no way to get key");
		free(te);
		return -1;
	}

	g = &grants[i];

	for(i = 0; i < nelem(cattrs) + 1; i++){
		if(i < nelem(cattrs))
			s = cattrs[i];
		else if(i == nelem(cattrs))
			s = g->attr;
		if(s[0] == '!'){
			a = k->privattr;
			p[i].s = s + 1;
		} else{
			a = k->attr;
			p[i].s = s;
		}
		if((p[i].t = _strfindattr(a, s)) == nil){
			werrstr("%s not found", s);
			free(te);
			return -1;
		}
	}
	p[nelem(cattrs) + 1] = (Pair){"grant_type", g->type};
	pa.n = nelem(p);
	pa.p = p;

	if((j = jsonhttp(Httppost, te, &pa)) == nil){
		werrstr("jsonhttp: %r");
		free(te);
		return -1;
	}
	free(te);

	if((t = jsonbyname(j, "error")) != nil){
		if(t->t == JSONString)
			werrstr("error getting token: %s", t->s);
		else
			werrstr("error getting token");
		jsonfree(j);
		return -1;
	}

	for(i = 0; i < nelem(jattrs); i++){
		s = jattrs[i];
		if(s[0] == '!'){
			a = k->privattr;
			t = jsonbyname(j, s + 1);
		} else {
			a = k->attr;
			t = jsonbyname(j, s);
		}
		if(t == nil)
			continue;
		if(t->t != JSONString){
			werrstr("%s is not a string", s);
			jsonfree(j);
			return -1;
		}
		b = _mkattr(AttrNameval, s, t->s, nil);
		setattrs(a, b);
		_freeattr(b);
	}

	t = jsonbyname(j, "expires_in");
	if(t != nil && t->t == JSONNumber){
		exptime = time(0) + (long)t->n;
		snprint(buf, sizeof buf, "%ld", exptime);
		b = _mkattr(AttrNameval, "exptime", buf, nil);
		setattrs(k->attr, b);
		_freeattr(b);
	}

	jsonfree(j);
	if(replacekey(k, 0) < 0){
		werrstr("replacekey: %r");
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
	fmtinstall('L', parrayfmt);
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
	char buf[4096];
	char *accesstoken, *idtoken;
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

Proto oauth =
{
.name=		"oauth",
.init=		oauthinit,
.write=		oauthwrite,
.read=		oauthread,
.close=		oauthclose,
.addkey=		replacekey,
.keyprompt=	"issuer? clientid? !clientsecret?",
};

