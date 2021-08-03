#include "dat.h"
#include <ctype.h>
#include <json.h>

#define USER_AGENT    "oauthtest"

int	urlencodefmt(Fmt*);

// Wrapper to hide whether we're using OpenSSL or macOS' libNetwork for HTTPS.

typedef struct Protocol Protocol;
typedef struct Pfd Pfd;
struct Protocol
{
	Pfd *(*connect)(char *host);
	int (*read)(Pfd*, void*, int);
	int (*write)(Pfd*, void*, int);
	void (*close)(Pfd*);
};

Protocol https;


// HTTP library

typedef struct HTTPHeader HTTPHeader;
struct HTTPHeader
{
	int code;
	char proto[100];
	char codedesc[100];
	vlong contentlength;
	char contenttype[100];
};

char *httpreq(Protocol *proto, char *host, char *request, HTTPHeader *hdr);

// JSON RPC

enum
{
	MaxResponse = 1<<29,
};

JSON*	urlpost(char *s, char *user, char *pass, char *name1, ...);
JSON*	urlget(char *s);
JSON*	jsonrpc(Protocol *proto, char *host, char *path, char *request, char *user, char *pass);


enum
{
	STACKSIZE = 32768
};

// URL parser
enum {
	Domlen = 256,
};

typedef struct Url Url;
struct Url
{
	char	*scheme;
	char	*user;
	char	*pass;
	char	*host;
	char	*port;
	char	*path;
	char	*query;
	char	*fragment;
};


char*	Upath(Url *);
Url*	url(char *s);
Url*	saneurl(Url *u);
void	freeurl(Url *u);

// idn

int	idn2utf(char *name, char *buf, int nbuf);

// flows


struct Pfd
{
	int fd;
};

static int
tlswrap(int fd, char *servername)
{
	TLSconn conn;

	memset(&conn, 0, sizeof(conn));
	if(servername != nil)
		conn.serverName = servername;
	if((fd = tlsClient(fd, &conn)) < 0){
		werrstr("tlsClient: %r");
	}
	free(conn.cert);
	free(conn.sessionID);
	return fd;
}

static Pfd*
httpconnect(char *host)
{
	char buf[1024];
	Pfd *pfd;
	int fd;

	snprint(buf, sizeof buf, "tcp!%s!http", host);
	if((fd = dial(buf, nil, nil, nil)) < 0)
		return nil;
	if((fd = tlswrap(fd, host)) < 0)
		return nil;
	pfd = emalloc(sizeof *pfd);
	pfd->fd = fd;
	return pfd;
}

static void
httpclose(Pfd *pfd)
{
	if(pfd == nil)
		return;
	close(pfd->fd);
	free(pfd);
}

static int
httpwrite(Pfd *pfd, void *v, int n)
{
	return writen(pfd->fd, v, n);
}

static int
httpread(Pfd *pfd, void *v, int n)
{
	return read(pfd->fd, v, n);
}

Protocol https = {
	httpconnect,
	httpread,
	httpwrite,
	httpclose,
};

enum
{
	Verifierlen = 100,
	Statelen = 32,
};

typedef struct Elem Elem;
struct Elem
{
	char *name;
	int type;
	long off;
};

typedef struct Discovery Discovery;
struct Discovery
{
	char *authorization_endpoint;
	char *token_endpoint;
	char *device_authorization_endpoint;
};

static Elem discelems[] =
{
	{"authorization_endpoint", JSONString, offsetof(Discovery, authorization_endpoint)},
	{"token_endpoint", JSONString, offsetof(Discovery, token_endpoint)},
	{"device_authorization_endpoint", JSONString, offsetof(Discovery, device_authorization_endpoint)},
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
	{"access_token", JSONString, offsetof(Tokenresp, access_token)},
	/* {"id_token", JSONString, offsetof(Tokenresp, id_token)}, we can't use this */
	{"token_type", JSONString, offsetof(Tokenresp, token_type)},
	{"expires_in", JSONNumber, offsetof(Tokenresp, expires_in)},
	{"refresh_token", JSONString, offsetof(Tokenresp, refresh_token)},
	{"scope", JSONString, offsetof(Tokenresp, scope)},
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
	{"device_code", JSONString, offsetof(Deviceresp, device_code)},
	{"user_code", JSONString, offsetof(Deviceresp, user_code)},
	{"verification_url", JSONString, offsetof(Deviceresp, verification_uri)}, /* google misspells this field */
	{"verification_uri", JSONString, offsetof(Deviceresp, verification_uri)},
	{"expires_in", JSONNumber, offsetof(Deviceresp, expires_in)},
	{"interval", JSONNumber, offsetof(Deviceresp, interval)},
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

void
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

int
readjson(JSON *j, Elem* e, int n, void *out)
{
	int i;
	JSON *t;
	for(i = 0; i < n; i++){
		if((t = jsonbyname(j, e[i].name)) == nil){
			/* it's okay if a key is missing */
			continue;
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

int
discoveryget(char *issuer, Discovery *disc)
{
	/* TODO: support multiple issuers per host and validate the issuer */
	JSON *jv;

	jv = jsonrpc(&https, issuer, "/.well-known/openid-configuration", nil, nil, nil);
	if(jv == nil){
		werrstr("jsonrpc: %r");
		return -1;
	}

	if(readjson(jv, discelems, nelem(discelems), disc) < 0){
		werrstr("readjson: %r");
		jsonfree(jv);
		return -1;
	}

	if(disc->authorization_endpoint == nil){
		werrstr("no authorization_endpoint");
		return -1;
	}

	if(disc->token_endpoint == nil){
		werrstr("no token_endpoint");
		return -1;
	}

	return 0;

}

int
printkey(char *issuer, char *client_id, char *client_secret, char *scope, JSON *j)
{
	Tokenresp tr;
	long exptime;

	memset(&tr, 0, sizeof tr);
	if(readjson(j, trelems, nelem(trelems), &tr) < 0){
		werrstr("readjson: %r");
		return -1;
	}
	if(tr.token_type == nil || tr.access_token == nil){
		werrstr("missing key");
		jsondestroy(trelems, nelem(trelems), &tr);
		return -1;
	}


	if(tr.expires_in == 0)
		tr.expires_in = (long)1800; /* picked at random */

	exptime = time(0) + (long)tr.expires_in;

	/* do not modify scope if the server modifies it, as we can't match on the scope if we change it */
	print("key proto=oauth issuer=%q client_id=%q token_type=%q exptime=%ld scope=%q", issuer, client_id, tr.token_type, exptime, scope);
	print(" !client_secret=%q !access_token=%q", client_secret, tr.access_token);
	if(tr.refresh_token != nil)
		print(" !refresh_token=%q", tr.refresh_token);
	print("\n");


	jsondestroy(trelems, nelem(trelems), &tr);
	return 0;
}


int
deviceflow(char *issuer, char *scope, char *client_id, char *client_secret)
{
	char errbuf[ERRMAX];
	Discovery disc;
	Deviceresp dr;
	JSON *j;
	int r;

	memset(&disc, 0, sizeof disc);
	memset(&dr, 0, sizeof dr);

	r = discoveryget(issuer, &disc);
	if(r < 0){
		werrstr("flowinit: %r");
		goto out;
	}

	dr.interval = 5;
	j = urlpost(disc.device_authorization_endpoint, nil, nil, "scope", scope, "client_id", client_id, nil);
	if(j == nil){
		r = -1;
		werrstr("urlpost device_authorization_endpoint: %r");
		goto out;
	}
	r = readjson(j, drelems, nelem(drelems), &dr);
	if(r < 0){
		werrstr("readjson: %r");
		goto out;
	}
	if(dr.verification_uri == nil || dr.user_code == nil || dr.device_code == nil){
		r = -1;
		werrstr("missing key");
		goto out;
	}
	fprint(2, "verification_uri=%q user_code=%q", dr.verification_uri, dr.user_code);
	for(;;sleep((long)dr.interval * 1000L)){
		j = urlpost(disc.token_endpoint, client_id, client_secret,
		            "grant_type", "urn:ietf:params:oauth:grant-type:device_code",
		            "device_code", dr.device_code,
		            nil);
		if(j == nil){
			/* check for special errors, don't give up yet */
			rerrstr(errbuf, sizeof errbuf);
			if(strstr(errbuf, "authorization_pending") != nil){
				continue;
			}
			if(strstr(errbuf, "slow_down") != nil){
				dr.interval += 5;
				continue;
			}
			r = -1;
			werrstr("urlpost token_endpoint: %r");
			goto out;
		}
		break;
	}
	r = printkey(issuer, client_id, client_secret, scope, j);
	if(r < 0){
		werrstr("printkey: %r");
		goto out;
	}
	r = 0;
	out:
	jsondestroy(drelems, nelem(drelems), &dr);
	jsondestroy(discelems, nelem(discelems), &disc);
	return r;
}

int
refreshflow(char *issuer, char *scope, char *client_id, char *client_secret, char *refresh_token)
{
	Discovery disc;
	JSON *j;
	int r;

	r = discoveryget(issuer, &disc);
	if(r < 0){
		werrstr("discoveryget: %r");
		goto out;
	}

	j = urlpost(disc.token_endpoint, client_id, client_secret,
	            "grant_type", "refresh_token",
	            "refresh_token", refresh_token,
	            nil);

	if(j == nil){
		r = -1;
		werrstr("urlpost: %r");
		goto out;
	}

	r = printkey(issuer, client_id, client_secret, scope, j);
	if(r < 0){
		werrstr("printkey: %r");
		goto out;
	}

	r = 0;
	out:
	jsondestroy(discelems, nelem(discelems), &disc);
	return r;
}

static char*
haveheader(char *buf, int n)
{
	int i;

	for(i=0; i<n; i++){
		if(buf[i] == '\n'){
			if(i+2 < n && buf[i+1] == '\r' && buf[i+2] == '\n')
				return buf+i+3;
			if(i+1 < n && buf[i+1] == '\n')
				return buf+i+2;
		}
	}
	return 0;
}

static int
parseheader(char *buf, int n, HTTPHeader *hdr)
{
	int nline;
	char *data, *ebuf, *p, *q, *next;

	memset(hdr, 0, sizeof *hdr);
	ebuf = buf+n;
	data = haveheader(buf, n);
	if(data == nil)
		return -1;

	data[-1] = 0;
	if(data[-2] == '\r')
		data[-2] = 0;
	nline = 0;
	for(p=buf; *p; p=next, nline++){
		q = strchr(p, '\n');
		if(q){
			next = q+1;
			*q = 0;
			if(q > p && q[-1] == '\r')
				q[-1] = 0;
		}else
			next = p+strlen(p);
		if(nline == 0){
			if(memcmp(p, "HTTP/", 5) != 0){
				werrstr("invalid HTTP version: %.10s", p);
				return -1;
			}
			q = strchr(p, ' ');
			if(q == nil){
				werrstr("invalid HTTP version");
				return -1;
			}
			*q++ = 0;
			strncpy(hdr->proto, p, sizeof hdr->proto);
			hdr->proto[sizeof hdr->proto-1] = 0;
			while(*q == ' ')
				q++;
			if(*q < '0' || '9' < *q){
				werrstr("invalid HTTP response code");
				return -1;
			}
			p = q;
			q = strchr(p, ' ');
			if(q == nil)
				q = p+strlen(p);
			else
				*q++ = 0;
			hdr->code = strtol(p, &p, 10);
			if(*p != 0)
				return -1;
			while(*q == ' ')
				q++;
			strncpy(hdr->codedesc, q, sizeof hdr->codedesc);
			hdr->codedesc[sizeof hdr->codedesc-1] = 0;
			continue;
		}
		q = strchr(p, ':');
		if(q == nil)
			continue;
		*q++ = 0;
		while(*q != 0 && (*q == ' ' || *q == '\t'))
			q++;
		if(cistrcmp(p, "Content-Type") == 0){
			strncpy(hdr->contenttype, q, sizeof hdr->contenttype);
			hdr->contenttype[sizeof hdr->contenttype-1] = 0;
			continue;
		}
		if(cistrcmp(p, "Content-Length") == 0 && '0' <= *q && *q <= '9'){
			hdr->contentlength = strtoll(q, 0, 10);
			continue;
		}
	}
	if(nline < 1){
		werrstr("no header");
		return -1;
	}

	memmove(buf, data, ebuf - data);
	return ebuf - data;
}

static char*
genhttp(Protocol *proto, char *host, char *req, HTTPHeader *hdr)
{
	int n, m, total, want;
	char buf[8192], *data;
	Pfd *fd;

	fd = proto->connect(host);
	if(fd == nil){
		werrstr("connect %s: %r", host);
		return nil;
	}

	n = strlen(req);
	if(proto->write(fd, req, n) != n){
		werrstr("write %s: %r", host);
		proto->close(fd);
		return nil;
	}

	total = 0;
	while(!haveheader(buf, total)){
		n = proto->read(fd, buf+total, sizeof buf-total);
		if(n <= 0){
			werrstr("read missing header");
			proto->close(fd);
			return nil;
		}
		total += n;
	}

	n = parseheader(buf, total, hdr);
	if(n < 0){
		werrstr("failed response parse: %r");
		proto->close(fd);
		return nil;
	}
	if(hdr->contentlength == 0)
		hdr->contentlength = -1; /* google doesn't send a content-length header */
	if(hdr->contentlength >= MaxResponse){
		werrstr("response too long");
		proto->close(fd);
		return nil;
	}
	if(hdr->contentlength >= 0 && n > hdr->contentlength)
		n = hdr->contentlength;
	want = sizeof buf;
	data = nil;
	total = 0;
	goto didread;

	while(want > 0 && (n = proto->read(fd, buf, want)) > 0){
	didread:
		data = erealloc(data, total+n);
		memmove(data+total, buf, n);
		total += n;
		if(total > MaxResponse){
			proto->close(fd);
			werrstr("response too long");
			return nil;
		}
		if(hdr->contentlength >= 0 && total + want > hdr->contentlength)
			want = hdr->contentlength - total;
	}
	proto->close(fd);

	if(hdr->contentlength >= 0 && total != hdr->contentlength){
		werrstr("got wrong content size %d %d", total, hdr->contentlength);
		return nil;
	}
	hdr->contentlength = total;
	data = erealloc(data, total+1);
	data[total] = 0;
	return data;
}

char*
httpreq(Protocol *proto, char *host, char *req, HTTPHeader *hdr)
{
	return genhttp(proto, host, req, hdr);
}

enum {
	base = 36,
	tmin = 1,
	tmax = 26,
	skew = 38,
	damp = 700,
	initial_bias = 72,
	initial_n = 0x80,

	Domlen = 256,
};

static uint maxint = ~0;

static uint
decode_digit(uint cp)
{
	if((cp - '0') < 10)
		return cp - ('0' - 26);
	if((cp - 'A') < 26)
		return cp - 'A';
	if((cp - 'a') < 26)
		return cp - 'a';
	return base;
}

static char
encode_digit(uint d, int flag)
{
	if(d < 26)
		return d + (flag ? 'A' : 'a');
	return d + ('0' - 26);
}

static uint
adapt(uint delta, uint numpoints, int firsttime)
{
	uint k;

	delta = firsttime ? delta / damp : delta >> 1;
	delta += delta / numpoints;
	for (k = 0; delta > ((base - tmin) * tmax) / 2; k += base)
		delta /= base - tmin;
	return k + (base - tmin + 1) * delta / (delta + skew);
}

static int
punyencode(uint input_length, Rune input[], uint max_out, char output[])
{
	uint n, delta, h, b, out, bias, j, m, q, k, t;

	n = initial_n;
	delta = out = 0;
	bias = initial_bias;

	for (j = 0;  j < input_length;  ++j) {
		if ((uint)input[j] < 0x80) {
			if (max_out - out < 2)
				return -1;
			output[out++] = input[j];
		}
	}

	h = b = out;

	if (b > 0)
		output[out++] = '-';

	while (h < input_length) {
		for (m = maxint, j = 0; j < input_length; ++j) {
			if (input[j] >= n && input[j] < m)
				m = input[j];
		}

		if (m - n > (maxint - delta) / (h + 1))
			return -1;

		delta += (m - n) * (h + 1);
		n = m;

		for (j = 0;  j < input_length;  ++j) {
			if (input[j] < n) {
				if (++delta == 0)
					return -1;
			}

			if (input[j] == n) {
				for (q = delta, k = base;; k += base) {
					if (out >= max_out)
						return -1;
					if (k <= bias)
						t = tmin;
					else if (k >= bias + tmax)
						t = tmax;
					else
						t = k - bias;
					if (q < t)
						break;
					output[out++] = encode_digit(t + (q - t) % (base - t), 0);
					q = (q - t) / (base - t);
				}
				output[out++] = encode_digit(q, isupperrune(input[j]));
				bias = adapt(delta, h + 1, h == b);
				delta = 0;
				++h;
			}
		}

		++delta, ++n;
	}

	return (int)out;
}

static int
punydecode(uint input_length, char input[], uint max_out, Rune output[])
{
	uint n, out, i, bias, b, j, in, oldi, w, k, digit, t;

	n = initial_n;
	out = i = 0;
	bias = initial_bias;

	for (b = j = 0; j < input_length; ++j)
		if (input[j] == '-')
			b = j;

	if (b > max_out)
		return -1;

	for (j = 0;  j < b;  ++j) {
		if (input[j] & 0x80)
			return -1;
		output[out++] = input[j];
	}

	for (in = b > 0 ? b + 1 : 0; in < input_length; ++out) {
		for (oldi = i, w = 1, k = base;; k += base) {
			if (in >= input_length)
				return -1;
			digit = decode_digit(input[in++]);
			if (digit >= base)
				return -1;
			if (digit > (maxint - i) / w)
				return -1;
			i += digit * w;
			if (k <= bias)
				t = tmin;
			else if (k >= bias + tmax)
				t = tmax;
			else
				t = k - bias;
			if (digit < t)
				break;
			if (w > maxint / (base - t))
				return -1;
			w *= (base - t);
		}

		bias = adapt(i - oldi, out + 1, oldi == 0);

		if (i / (out + 1) > maxint - n)
			return -1;
		n += i / (out + 1);
		i %= (out + 1);

		if (out >= max_out)
			return -1;

		memmove(output + i + 1, output + i, (out - i) * sizeof *output);
		if(((uint)input[in-1] - 'A') < 26)
			output[i++] = toupperrune(n);
		else
			output[i++] = tolowerrune(n);
	}

	return (int)out;
}

/*
 * convert punycode encoded internationalized
 * domain name to unicode string
 */
int
idn2utf(char *name, char *buf, int nbuf)
{
	char *dp, *de, *cp;
	Rune rb[Domlen], r;
	int nc, nr, n;

	cp = name;
	dp = buf;
	de = dp+nbuf-1;
	for(;;){
		nc = nr = 0;
		while(cp[nc] != 0){
			n = chartorune(&r, cp+nc);
			if(r == '.')
				break;
			rb[nr++] = r;
			nc += n;
		}
		if(cistrncmp(cp, "xn--", 4) == 0)
			if((nr = punydecode(nc-4, cp+4, nelem(rb), rb)) < 0)
				return -1;
		dp = seprint(dp, de, "%.*S", nr, rb);
		if(dp >= de)
			return -1;
		if(cp[nc] == 0)
			break;
		*dp++ = '.';
		cp += nc+1;
	}
	*dp = 0;
	return dp - buf;
}

/*
 * convert unicode string to punycode
 * encoded internationalized domain name
 */
int
utf2idn(char *name, char *buf, int nbuf)
{
	char *dp, *de, *cp;
	Rune rb[Domlen], r;
	int nc, nr, n;

	dp = buf;
	de = dp+nbuf-1;
	cp = name;
	for(;;){
		nc = nr = 0;
		while(cp[nc] != 0 && nr < nelem(rb)){
			n = chartorune(&r, cp+nc);
			if(r == '.')
				break;
			rb[nr++] = r;
			nc += n;
		}
		if(nc == nr)
			dp = seprint(dp, de, "%.*s", nc, cp);
		else {
			dp = seprint(dp, de, "xn--");
			if((n = punyencode(nr, rb, de - dp, dp)) < 0)
				return -1;
			dp += n;
		}
		if(dp >= de)
			return -1;
		if(cp[nc] == 0)
			break;
		*dp++ = '.';
		cp += nc+1;
	}
	*dp = 0;
	return dp - buf;
}


// JSON RPC over HTTP

static char*
makehttprequest(char *host, char *path, char *postdata, char *user, char *pass)
{
	Fmt fmt;
	char buf[512];

	fmtstrinit(&fmt);
	if(postdata){
		fmtprint(&fmt, "POST %s HTTP/1.0\r\n", path);
		fmtprint(&fmt, "Host: %s\r\n", host);
		fmtprint(&fmt, "User-Agent: " USER_AGENT "\r\n");
		if(user){
			snprint(buf, sizeof buf, "%s:%s", user ? user : "", pass ? pass : "");
			fmtprint(&fmt, "Authorization: Basic %.*[\r\n", strlen(buf), buf);
		}
		fmtprint(&fmt, "Content-Type: application/x-www-form-urlencoded\r\n");
		fmtprint(&fmt, "Content-Length: %d\r\n", strlen(postdata));
		fmtprint(&fmt, "\r\n");
		fmtprint(&fmt, "%s", postdata);
	} else{
		fmtprint(&fmt, "GET %s HTTP/1.0\r\n", path);
		fmtprint(&fmt, "Host: %s\r\n", host);
		fmtprint(&fmt, "User-Agent: " USER_AGENT "\r\n");
		fmtprint(&fmt, "\r\n");
	}
	return fmtstrflush(&fmt);
}

static char*
makerequest(char *name1, va_list arg)
{
	char *p, *key, *val;
	Fmt fmt;
	int first;

	fmtstrinit(&fmt);
	first = 1;
	p = name1;
	while(p != nil){
		key = p;
		val = va_arg(arg, char*);
		if(val == nil){
			werrstr("jsonrpc: nil value");
			free(fmtstrflush(&fmt));
			return nil;
		}
		fmtprint(&fmt, first + "&%U=%U", key, val);
		first = 0;
		p = va_arg(arg, char*);
	}
	return fmtstrflush(&fmt);
}

static char*
dojsonhttp(Protocol *proto, char *host, char *request)
{
	char *data;
	HTTPHeader hdr;

	data = httpreq(proto, host, request, &hdr);
	if(data == nil){
		werrstr("httpreq: %r");
		return nil;
	}
	if(strstr(hdr.contenttype, "application/json") == nil){
		werrstr("bad content type: %s", hdr.contenttype);
		return nil;
	}
	if(hdr.contentlength == 0){
		werrstr("no content");
		return nil;
	}
	return data;
}

JSON*
jsonrpc(Protocol *proto, char *host, char *path, char *request, char *user, char *pass)
{
	char *httpreq, *reply;
	JSON *jv, *jerror;

	httpreq = makehttprequest(host, path, request, user, pass);
	free(request);

	if((reply = dojsonhttp(proto, host, httpreq)) == nil){
		free(httpreq);
		return nil;
	}
	free(httpreq);

	jv = jsonparse(reply);
	free(reply);
	if(jv == nil){
		werrstr("error parsing JSON reply: %r");
		return nil;
	}

	if((jerror = jsonbyname(jv, "error")) == nil){
		return jv;
	}

	werrstr("%J", jerror);
	jsonfree(jv);
	return nil;
}

JSON*
urlpost(char *s, char *user, char *pass, char *name1, ...)
{
	JSON *jv;
	va_list arg;
	Url *u;

	if((u = saneurl(url(s))) == nil){
		werrstr("url parsing error");
		return nil;
	}

	va_start(arg, name1);
	jv = jsonrpc(&https, u->host, Upath(u), makerequest(name1, arg), user, pass);
	va_end(arg);
	freeurl(u);
	return jv;
}

JSON*
urlget(char *s)
{
	JSON *jv;
	Url *u;

	if((u = saneurl(url(s))) == nil){
		werrstr("url parsing error");
		return nil;
	}

	jv = jsonrpc(&https, u->host, Upath(u), nil, nil, nil);
	freeurl(u);
	return jv;
}



/* 9front /sys/src/cmd/webfs/url.c */

static char reserved[] = "%:/?#[]@!$&'()*+,;=";

static int
dhex(char c)
{
	if('0' <= c && c <= '9')
		return c-'0';
	if('a' <= c && c <= 'f')
		return c-'a'+10;
	if('A' <= c && c <= 'F')
		return c-'A'+10;
	return 0;
}

static char*
unescape(char *s, char *spec)
{
	char *r, *w;
	uchar x;

	if(s == nil)
		return s;
	for(r=w=s; x = *r; r++){
		if(x == '%' && isxdigit(r[1]) && isxdigit(r[2])){
			x = (dhex(r[1])<<4)|dhex(r[2]);
			if(spec && strchr(spec, x)){
				*w++ = '%';
				*w++ = toupper(r[1]);
				*w++ = toupper(r[2]);
			}
			else
				*w++ = x;
			r += 2;
			continue;
		}
		*w++ = x;
	}
	*w = 0;
	return s;
}


char*
Upath(Url *u)
{
	if(u){
		if(u->path)
			return u->path;
		if(u->user || u->host)
			return "/";
	}
	return nil;
}

static char*
remdot(char *s)
{
	char *b, *d, *p;
	int dir, n;

	dir = 1;
	b = d = s;
	if(*s == '/')
		s++;
	for(; s; s = p){
		if(p = strchr(s, '/'))
			*p++ = 0;
		if(*s == '.' && ((s[1] == 0) || (s[1] == '.' && s[2] == 0))){
			if(s[1] == '.')
				while(d > b)
					if(*--d == '/')
						break;
			dir = 1;
			continue;
		} else
			dir = (p != nil);
		if((n = strlen(s)) > 0)
			memmove(d+1, s, n);
		*d++ = '/';
		d += n;
	}
	if(dir)
		*d++ = '/';
	*d = 0;
	return b;
}

static char*
abspath(char *s, char *b)
{
	char *x, *a;

	if(b && *b){
		if(s == nil || *s == 0)
			return estrdup(b);
		if(*s != '/' && (x = strrchr(b, '/'))){
			a = emalloc((x - b) + strlen(s) + 4);
			sprint(a, "%.*s/%s", utfnlen(b, x - b), b, s);
			return remdot(a);
		}
	}
	if(s && *s){
		if(*s != '/')
			return estrdup(s);
		a = emalloc(strlen(s) + 4);
		sprint(a, "%s", s);
		return remdot(a);
	}
	return nil;
}

static void
pstrdup(char **p)
{
	if(p == nil || *p == nil)
		return;
	if(**p == 0){
		*p = nil;
		return;
	}
	*p = estrdup(*p);
}

static char*
mklowcase(char *s)
{
	char *cp;
	Rune r;

	if(s == nil)
		return s;
	cp = s;
	while(*cp != 0){
		chartorune(&r, cp);
		r = tolowerrune(r);
		cp += runetochar(cp, &r);
	}
	return s;
}

Url*
url(char *s)
{
	char *t, *p, *x, *y;
	Url *u;

	if(s == nil)
		s = "";
	t = nil;
	s = p = estrdup(s);
	u = emalloc(sizeof(*u));
	for(; *p; p++){
		if(*p == ':'){
			if(p == s)
				break;
			*p++ = 0;
			u->scheme = s;
			goto Abs;
		}
		if(!isalpha(*p))
			if((p == s) || ((!isdigit(*p) && strchr("+-.", *p) == nil)))
				break;
	}
	p = s;
Abs:
	if(x = strchr(p, '#')){
		*x = 0;
		u->fragment = x+1;
	}
	if(x = strchr(p, '?')){
		*x = 0;
		u->query = x+1;
	}
	if(p[0] == '/' && p[1] == '/'){
		p += 2;
		if(x = strchr(p, '/')){
			u->path = t = abspath(x, nil);
			*x = 0;
		}
		if(x = strchr(p, '@')){
			*x = 0;
			if(y = strchr(p, ':')){
				*y = 0;
				u->pass = y+1;
			}
			u->user = p;
			p = x+1;
		}
		if((x = strrchr(p, ']')) == nil)
			x = p;
		if(x = strrchr(x, ':')){
			*x = 0;
			u->port = x+1;
		}
		if(x = strchr(p, '[')){
			p = x+1;
			if(y = strchr(p, ']'))
				*y = 0;
		}
		u->host = p;
	} else {
		u->path = t = abspath(p, nil);
	}
Out:
	pstrdup(&u->scheme);
	pstrdup(&u->user);
	pstrdup(&u->pass);
	pstrdup(&u->host);
	pstrdup(&u->port);
	pstrdup(&u->path);
	pstrdup(&u->query);
	pstrdup(&u->fragment);
	free(s);
	free(t);

	/* the + character encodes space only in query part */
	if(s = u->query)
		while(s = strchr(s, '+'))
			*s++ = ' ';

	if(s = u->host){
		t = emalloc(Domlen);
		if(idn2utf(s, t, Domlen) >= 0){
			u->host = estrdup(t);
			free(s);
		}
		free(t);
	}

	unescape(u->user, nil);
	unescape(u->pass, nil);
	unescape(u->path, reserved);
	unescape(u->query, reserved);
	unescape(u->fragment, reserved);
	mklowcase(u->scheme);
	mklowcase(u->host);
	mklowcase(u->port);

	return u;
}

Url*
saneurl(Url *u)
{
	if(u == nil || u->scheme == nil || u->host == nil || Upath(u) == nil){
		freeurl(u);
		return nil;
	}
	if(u->port){
		/* remove default ports */
		switch(atoi(u->port)){
		case 21:	if(!strcmp(u->scheme, "ftp"))	goto Defport; break;
		case 70:	if(!strcmp(u->scheme, "gopher"))goto Defport; break;
		case 80:	if(!strcmp(u->scheme, "http"))	goto Defport; break;
		case 443:	if(!strcmp(u->scheme, "https"))	goto Defport; break;
		default:	if(!strcmp(u->scheme, u->port))	goto Defport; break;
		Defport:
			free(u->port);
			u->port = nil;
		}
	}
	return u;
}


void
freeurl(Url *u)
{
	if(u == nil)
		return;
	free(u->scheme);
	free(u->user);
	free(u->pass);
	free(u->host);
	free(u->port);
	free(u->path);
	free(u->query);
	free(u->fragment);
	free(u);
}

int
urlencodefmt(Fmt *fmt)
{
	int x;
	char *s;

	s = va_arg(fmt->args, char*);
	for(; *s; s++){
		x = (uchar)*s;
		if(x == ' ')
			fmtrune(fmt, '+');
		else if(('a' <= x && x <= 'z') || ('A' <= x && x <= 'Z') || ('0' <= x && x <= '9')
			|| strchr("$-_.+!*'()", x)){
			fmtrune(fmt, x);
		}else
			fmtprint(fmt, "%%%02ux", x);
	}
	return 0;
}

void
usage(void)
{
	fprint(2, "usage: oauth [-dr] issuer scope client_id client_secret [refresh_token]\n");
	threadexitsall("usage");
}

void
threadmain(int argc, char **argv)
{
	int usedev;
	int useref;
	char *issuer, *scope, *client_id, *client_secret, *refresh_token;

	usedev = 0;
	useref = 0;
	ARGBEGIN{
	default:
		usage();
	case 'd':
		usedev++;
		break;
	case 'r':
		useref++;
		break;
	}ARGEND

	if(argc != 3 && argc != 4 && argc != 5)
		usage();

	quotefmtinstall();
	fmtinstall('[', encodefmt);  // base-64
	fmtinstall('J', JSONfmt);
	fmtinstall('U', urlencodefmt);

	issuer = argv[0];
	scope = argv[1];
	client_id = argv[2];
	client_secret = argv[3];
	if(useref){
		if(argc != 5){
			sysfatal("missing refresh token");
		}
		refresh_token = argv[4];
		if(refreshflow(issuer, scope, client_id, client_secret, refresh_token) < 0){
			sysfatal("refreshflow: %r");
		}
	} else if(usedev){
		if(deviceflow(issuer, scope, client_id, client_secret) < 0){
			sysfatal("deviceflow: %r");
		}
	} else{
		sysfatal("no flow specified");
	}

	threadexitsall(nil);
}
