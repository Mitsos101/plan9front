#include <u.h>
#include <libc.h>
#include <auth.h>

void
usage(void)
{
	fprint(2, "usage: auth/oauth fmt\n");
	exits("usage");
}

int
oauth_getkey(char *params)
{
	Attr *a;
	char *verification_uri;
	char *user_code;

	if((a = _parseattr(params)) == nil)
		return auth_getkey(params);

	 if((verification_uri = _strfindattr(a, "verification_uri")) == nil
	 || (user_code = _strfindattr(a, "user_code")) == nil){
	 	_freeattr(a);
	 	return auth_getkey(params);
	 }

	 fprint(2, "go to %s\n", verification_uri);
	 fprint(2, "your code is %s\n", user_code);

	 return 0;
}

void
main(int argc, char **argv)
{
	OAuth *o;

	ARGBEGIN{
	default:
		usage();
	}ARGEND

	if(argc != 1)
		usage();

	o = auth_getoauth(oauth_getkey, "proto=oauth %s", argv[0]);
	if(o == nil)
		sysfatal("getoauth: %r");

	quotefmtinstall();
	print("%q\n", o->access_token);
	exits(0);
}
