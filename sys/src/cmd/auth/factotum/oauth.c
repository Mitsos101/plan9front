#include "dat.h"


enum {
	Httpget,
	Httppost,
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
			if(fprint(ctlfd, "url %s%P", url, sp) < 0){
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
	setattrs(fss->attr, k->attr);
	s = emalloc(sizeof(*s));
	s->key = k;
	fss->ps = s;
	fss->phase = HavePass;
	return RpcOk;
}
