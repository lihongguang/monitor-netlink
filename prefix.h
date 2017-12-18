#ifndef _PREFIX_H_
#define _PREFIX_H_

#ifndef HAVE_IPV6
#define HAVE_IPV6
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif /* INET_ADDRSTRLEN */

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif /* INET6_ADDRSTRLEN */

#ifndef INET6_BUFSIZ
#define INET6_BUFSIZ 51
#endif /* INET6_BUFSIZ */

/*
 *  A struct prefix contains an address family, a prefix length, and an
 *  address.  This can represent either a 'network prefix' as defined
 *  by CIDR, where the 'host bits' of the prefix are 0
 *  (e.g. AF_INET:10.0.0.0/8), or an address and netmask
 *  (e.g. AF_INET:10.0.0.9/8), such as might be configured on an
 *  interface.
 */

/* IPv4 and IPv6 unified prefix structure. */
struct prefix
{
	u_char family;
	u_char prefixlen;
	union
	{
		u_char prefix;
		struct in_addr prefix4;
#ifdef HAVE_IPV6
		struct in6_addr prefix6;
#endif /* HAVE_IPV6 */
		struct
		{
			struct in_addr id;
			struct in_addr adv_router;
		} lp;
		u_char val[8];
		uintptr_t ptr;
	} u __attribute__ ((aligned (8)));
};

/* IPv4 prefix structure. */
struct prefix_ipv4
{
	u_char family;
	u_char prefixlen;
	struct in_addr prefix __attribute__ ((aligned (8)));
};

/* IPv6 prefix structure. */
#ifdef HAVE_IPV6
struct prefix_ipv6
{
	u_char family;
	u_char prefixlen;
	struct in6_addr prefix __attribute__ ((aligned (8)));
};
#endif /* HAVE_IPV6 */

#endif
