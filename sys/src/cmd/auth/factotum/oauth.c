#include "dat.h"
#include <httpd.h>
#include <json.h>

/* webfs and factotum need to be in the same namespace */
static int
bindwebfs(void)
{
	int srvfd;

	if(access("/mnt/web/ctl", AEXIST) < 0){
		if((srvfd = open("#s/web", ORDWR)) >= 0){
			if(mount(srvfd, -1, "/mnt/web", MREPL, "") != -1)
				return 0;
			close(srvfd);
		}
		return -1;
	}
	return 0;
}

char *webmtpt = "/mnt/web";

enum
{
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

typedef struct Elem Elem;
struct Elem
{
	char *name;
	int type;
	long off;
	int required;
};

static char *typename[] =
{
	[JSONNull] "JSONNull",
	[JSONBool] "JSONBool",
	[JSONNumber] "JSONNumber",
	[JSONString] "JSONString",
	[JSONArray] "JSONArray",
	[JSONObject] "JSONObject",
};

typedef struct Discovery Discovery;
struct Discovery
{
	char *device_authorization_endpoint;
	char *token_endpoint;
	char *userinfo_endpoint;
};

static Elem discelems[] =
{
	{"device_authorization_endpoint", JSONString, offsetof(Discovery, device_authorization_endpoint), 1},
	{"token_endpoint", JSONString, offsetof(Discovery, token_endpoint), 1},
	{"userinfo_endpoint", JSONString, offsetof(Discovery, userinfo_endpoint), 1},
};

typedef struct Deviceresp Deviceresp;
struct Deviceresp
{
	char *device_code;
	char *user_code;
	char *verification_url; /* this should be verification_uri according to rfc8628 but google uses this */
	double expires_in;
	double interval;
};

static Elem drelems[] =
{
	{"device_code", JSONString, offsetof(Deviceresp, device_code), 1},
	{"user_code", JSONString, offsetof(Deviceresp, user_code), 1},
	{"verification_url", JSONString, offsetof(Deviceresp, verification_url), 1},
	{"expires_in", JSONNumber, offsetof(Deviceresp, expires_in), 1},
	{"interval", JSONNumber, offsetof(Deviceresp, interval), 0},
};

typedef struct Tokenresp Tokenresp;
struct Tokenresp
{
	char *access_token;
	char *id_token;
	char *token_type;
	double expires_in;
	char *refresh_token;
	char *scope;
};

static Elem trelems[] =
{
	{"access_token", JSONString, offsetof(Tokenresp, access_token), 1},
	{"id_token", JSONString, offsetof(Tokenresp, id_token), 0},
	{"token_type", JSONString, offsetof(Tokenresp, token_type), 1},
	{"expires_in", JSONNumber, offsetof(Tokenresp, expires_in), 1}, /* this is set to required for simplicity */
	{"refresh_token", JSONString, offsetof(Tokenresp, refresh_token), 0},
	{"scope", JSONString, offsetof(Tokenresp, scope), 0},
};

#pragma varargck	type	"P"	Pair*
#pragma varargck	type	"L"	PArray*

static int
parrayfmt(Fmt *f)
{
	PArray *pa;
	int i, r;

	r = 0;
	pa = va_arg(f->args, PArray*);
	if(pa == nil)
		return 0;
	for(i = 0; i < pa->n; i++){
		if(i != 0) r += fmtprint(f, "&");
		r += fmtprint(f, "%P", &pa->p[i]);
	}

	return r;
}

static int
pairfmt(Fmt *f)
{
	Pair *p;
	int r;

	r = 0;
	p = va_arg(f->args, Pair*);
	r += fmtprint(f, "%U=%U", p->s, p->t);

	return r;
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
	char buf[1024], *s;
	int ctlfd, fd, conn, n;

	s = nil;
	fd = -1;
	snprint(buf, sizeof buf, "%s/clone", webmtpt);
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
			if(fprint(ctlfd, "url %s", url) < 0){
				werrstr("url ctl write: %r");
				goto out;
			}
			snprint(buf, sizeof buf, "%s/%d/postbody", webmtpt, conn);
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

	snprint(buf, sizeof buf, "%s/%d/body", webmtpt, conn);
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
jsonhttp(int meth, char *url, PArray *pa)
{
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

static void
jsondestroy(Elem *e, int n, void *out)
{
	int i;

	for(i = 0; i < n; i++){
		if(e[i].type == JSONString){
			free(*(char **)((char*)out + e[i].off));
			*(char**)((char*)out + e[i].off) = nil;
		}
	}
}


static int
readjson(JSON *j, Elem* e, int n, void *out)
{
	int i;
	JSON *t;
	for(i = 0; i < n; i++){
		if((t = jsonbyname(j, e[i].name)) == nil){
			if(!e[i].required)
				continue;
			werrstr("jsonbyname: %r");
			jsondestroy(e, n, out);
			return -1;
		}
		if(e[i].type != t->t){
			werrstr("types for key %s do not match: need %s, got %s", e[i].name, typename[e[i].type], typename[t->t]);
			jsondestroy(e, n, out);
			return -1;
		}
		switch(e[i].type){
		default:
			werrstr("no way to read type %s", typename[e[i].type]);
			jsondestroy(e, n, out);
			return -1;
		case JSONNumber:
			*(double *)((char*)out + e[i].off) = t->n;
			break;
		case JSONString:
			if((*(char **)((char*)out + e[i].off) = strdup(t->s)) == nil){
				werrstr("strdup: %r");
				jsondestroy(e, n, out);
				return -1;
			}
			break;
		}
	}
	return 0;
}

static int
readjsonhttp(int meth, char *url, PArray *pa, Elem* e, int n, void *out)
{
	JSON *j, *err;
	int r;
	if((j = jsonhttp(meth, url, pa)) == nil){
		werrstr("jsonhttp: %r");
		return -1;
	}
	/* check for error key for better diagnostics */
	if((err = jsonbyname(j, "error")) != nil && err->t == JSONString){
		werrstr("%s", err->s);
		jsonfree(j);
		return -1;
	}
	r = readjson(j, e, n, out);
	jsonfree(j);
	if(r < 0){
		werrstr("readjson: %r");
		return -1;
	}
	return 0;
}

static int
webfsctl(char *cmd)
{
	int fd;
	char buf[1024];

	snprint(buf, sizeof buf, "%s/ctl", webmtpt);
	if((fd = open(buf, OWRITE)) < 0){
		werrstr("open %s: %r", buf);
		return -1;
	}
	if(fprint(fd, "%s", cmd) < 0){
		werrstr("write %s: %r", buf);
		return -1;
	}
	return 0;
}

static int
flowinit(char *issuer, Discovery *disc)
{
	char buf[1024];
	int r;

	snprint(buf, sizeof buf, "%s%s", issuer, "/.well-known/openid-configuration");
	r = readjsonhttp(Httpget, buf, nil, discelems, nelem(discelems), disc);
	if(r < 0){
		werrstr("readjsonhttp openid-configuration: %r");
		return r;
	}

	snprint(buf, sizeof buf, "preauth %s %s", disc->token_endpoint, "oauth");
	r = webfsctl(buf);
	if(r < 0){
		werrstr("webfsctl: %r");
		return r;
	}

	return 0;
}

static int
updatekey(Key *k, char *issuer, char *client_id, Tokenresp *tr)
{
	setattr(k->attr, "proto=oauth issuer=%q client_id=%q token_type=%q exptime=%ld scope=%q",
	issuer, client_id, tr->token_type, time(0) + (long)tr->expires_in, tr->scope);
	setattr(k->privattr, "!access_token=%q", tr->access_token);
	if(tr->refresh_token != nil)
		setattr(k->privattr, "!refresh_token=%q", tr->refresh_token);
	print("\n");
	return 0;
}

static int
refreshflow(Key *k, char *issuer, char *scope, char *client_id, char *refresh_token)
{
	Pair p[2];
	Discovery disc;
	PArray pa;
	int r;
	Tokenresp tr;

	memset(&disc, 0, sizeof disc);
	memset(&tr, 0, sizeof tr);

	r = flowinit(issuer, &disc);
	if(r < 0){
		werrstr("flowinit: %r");
		goto out;
	}

	pa = (PArray){2, p};
	p[0] = (Pair){"grant_type", "refresh_token"};
	p[1] = (Pair){"refresh_token", refresh_token};
	r = readjsonhttp(Httppost, disc.token_endpoint, &pa, trelems, nelem(trelems), &tr);
	if(r < 0){
		werrstr("readjsonhttp token_endpoint: %r");
		goto out;
	}

	if(tr.scope == nil)
		tr.scope = scope;
	if(tr.refresh_token == nil)
		tr.refresh_token = refresh_token;
	r = updatekey(k, issuer, client_id, &tr);

	/* make sure those don't get freed */
	if(tr.scope == scope)
		tr.scope = nil;
	if(tr.refresh_token == refresh_token)
		tr.refresh_token = nil;

	if(r < 0){
		werrstr("updatekey: %r");
		goto out;
	}
	r = 0;
	out:
	jsondestroy(discelems, nelem(discelems), &disc);
	jsondestroy(trelems, nelem(trelems), &tr);
	return r;
}

static int
refresh(Key *k)
{
	char *issuer;
	char *scope;
	char *client_id;
	char *refresh_token;
	char *exptime;

	if((issuer = _strfindattr(k->attr, "issuer")) == nil){
		werrstr("issuer missing");
		return -1;
	}
	if((scope = _strfindattr(k->attr, "scope")) == nil){
		werrstr("scope missing");
		return -1;
	}
	if((client_id = _strfindattr(k->attr, "client_id")) == nil){
		werrstr("client_id missing");
		return -1;
	}
	if((refresh_token = _strfindattr(k->privattr, "!refresh_token")) == nil){
		werrstr("refresh_token missing");
		return -1;
	}
	if((exptime = _strfindattr(k->attr, "exptime")) != nil && atol(exptime) <= time(0))
		return 0;

	fmtinstall('U', hurlfmt);
	fmtinstall('P', pairfmt);
	fmtinstall('L', parrayfmt);
	if(bindwebfs() < 0){
		werrstr("bindwebfs: %r");
		return -1;
	}
	if(refreshflow(k, issuer, scope, client_id, refresh_token) < 0){
		werrstr("refreshflow: %r");
		return -1;
	}
	return replacekey(k, 0);
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
