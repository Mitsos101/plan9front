#include <u.h>
#include <libc.h>
#include <auth.h>

void
usage(void)
{
	fprint(2, "usage: auth/oauth fmt\n");
	exits("usage");
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

	o = auth_getoauth(auth_getkey, "proto=oauth %s", argv[0]);
	if(o == nil)
		sysfatal("getoauth: %r");

	quotefmtinstall();
	print("%q\n", o->access_token);
	exits(0);
}
