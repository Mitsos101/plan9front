#include <u.h>
#include <libc.h>
#include <json.h>
#include <httpd.h>

void*
erealloc(void *v, ulong sz)
{
	void *nv;

	if((nv = realloc(v, sz)) == nil && sz != 0) {
		fprint(2, "out of memory allocating %lud\n", sz);
		exits("mem");
	}
	if(v == nil)
		setmalloctag(nv, getcallerpc(&v));
	setrealloctag(nv, getcallerpc(&v));
	return nv;
}


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
};

static Elem discelems[] =
{
	{"device_authorization_endpoint", JSONString, offsetof(Discovery, device_authorization_endpoint), 1},
	{"token_endpoint", JSONString, offsetof(Discovery, token_endpoint), 1},
};

typedef struct Deviceresp Deviceresp;
struct Deviceresp
{
	char *device_code;
	char *user_code;
	char *verification_uri;
	double expires_in;
	double interval;
};

static Elem drelems[] =
{
	{"device_code", JSONString, offsetof(Deviceresp, device_code), 1},
	{"user_code", JSONString, offsetof(Deviceresp, user_code), 1},
	{"verification_uri", JSONString, offsetof(Deviceresp, verification_uri), 1},
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
	{"access_token", JSONString, offsetof(Tokenresp, access_token), 0},
	{"id_token", JSONString, offsetof(Tokenresp, id_token), 0},
	{"token_type", JSONString, offsetof(Tokenresp, token_type), 1},
	{"expires_in", JSONNumber, offsetof(Tokenresp, expires_in), 1}, /* this is set to required for simplicity */
	{"refresh_token", JSONString, offsetof(Tokenresp, refresh_token), 1}, /* this is set to required for simplicity */
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

void
jsondestroy(Elem *e, int n, void *out)
{
	int i;
	for(i = 0; i < n; i++){
		if(e->type == JSONString){
			free((char*)out + e->off);
		}
	}
}


int
readjson(JSON *j, Elem* e, int n, void *out)
{
	int i;
	JSON *t;
	for(i = 0; i < n; i++){
		if((t = jsonbyname(j, e->name)) == nil){
			if(!e->required)
				continue;
			werrstr("jsonbyname: %r");
			jsondestroy(e, n, out);
			return -1;
		}
		if(e->type != t->t){
			werrstr("types for key %s do not match: need %s, got %s", e->name, typename[e->type], typename[t->t]);
			jsondestroy(e, n, out);
			return -1;
		}
		switch(e->type){
		default:
			werrstr("no way to read type %s", typename[e->type]);
			jsondestroy(e, n, out);
			return -1;
		case JSONNumber:
			*(double *)((char*)out + e->off) = t->n;
			break;
		case JSONString:
			if((*(char **)((char*)out + e->off) = strdup(t->s)) == nil){
				werrstr("strdup: %r");
				jsondestroy(e, n, out);
				return -1;
			}
			break;
		}
	}
	return 0;
}

int
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

int
deviceflow(char *issuer, char *scope)
{
	char buf[1024];
	char errbuf[ERRMAX];
	Discovery disc;
	Deviceresp dr;
	Tokenresp tr;
	long deadline, exptime;
	Pair p[2];
	PArray pa;
	int r;

	memset(&disc, 0, sizeof disc);
	memset(&dr, 0, sizeof dr);
	memset(&tr, 0, sizeof tr);
	if(scope == nil){
		werrstr("scope missing");
		return -1;
	}
	if(issuer == nil){
		werrstr("issuer missing");
		return -1;
	}
	snprint(buf, sizeof buf, "%s%s", issuer, "/.well-known/openid-configuration");

	r = readjsonhttp(Httpget, buf, nil, discelems, nelem(discelems), &disc);
	if(r < 0){
		werrstr("readjsonhttp: %r");
		goto out;
	}
	dr.interval = 5;
	pa = (PArray){1, p};
	p[0] = (Pair){"scope", scope};
	r = readjsonhttp(Httppost, disc.device_authorization_endpoint, &pa, drelems, nelem(drelems), &dr);
	if(r < 0){
		werrstr("readjsonhttp: %r");
		goto out;
	}
	print("go to %s\n", dr.verification_uri);
	print("your code is %s\n", dr.user_code);
	p[0] = (Pair){"grant_type", "urn:ietf:params:oauth:grant-type:device_code"};
	p[1] = (Pair){"device_code", dr.device_code};
	pa = (PArray){2, p};
	for(deadline = time(0) + (long)dr.expires_in; time(0) < deadline; sleep((long)dr.interval)){
		r = readjsonhttp(Httppost, disc.token_endpoint, &pa, trelems, nelem(trelems), &tr);
		if(r < 0){
			jsondestroy(trelems, nelem(trelems), &tr);
			memset(tr, 0, sizeof tr);
			/* check for special errors, don't give up yet */
			rerrstr(errbuf, sizeof errbuf);
			if(strstr(errbuf, "authorization_pending") != nil){
				continue;
			}
			if(strstr(errbuf, "slow_down") != nil){
				dr.interval += 5;
				continue;
			}
			werrstr("readjsonhttp: %r");
			goto out;
		}
		break;
	}
	exptime = time(0) + (long)tr.expires_in;
	print("key proto=oauth token_type=%q exptime=%ld refresh_token=%q", tr.token_type, exptime, tr.refresh_token);
	if(tr.access_token != nil) print(" access_token=%q", tr.access_token);
	if(tr.id_token != nil) print(" id_token=%q", tr.id_token);
	if(tr.scope != nil) print(" scope=%q", tr.scope);
	print("\n");
	r = 0;
	out:
	jsondestroy(discelems, nelem(discelems), &disc);
	jsondestroy(drelems, nelem(drelems), &dr);
	jsondestroy(trelems, nelem(trelems), &tr);
	return r;
}

void
usage(void)
{
	fprint(2, "usage: deviceflow issuer scope");
	exits("usage");
}

void
main(int argc, char *argv[])
{
	char *issuer;
	char *scope;

	if(argc != 3){
		usage();
	}
	fmtinstall('P', pairfmt);
	fmtinstall('L', parrayfmt);
	quotefmtinstall();
	issuer = argv[1];
	scope = argv[2];
	if(deviceflow(issuer, scope) < 0){
		sysfatal("deviceflow: %r");
	}
	exits(0);
}
