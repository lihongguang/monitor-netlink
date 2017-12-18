#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>

#include "prefix.h"
#include "rt_netlink.h"

/* Socket interface to kernel */
struct nlsock
{
	int sock;
	int seq;
	struct sockaddr_nl snl;
	const char *name;
} netlink = { -1, 0, {0}, "netlink-listen"}; /* kernel messages */

static const struct message nlmsg_str[] = {
	{RTM_NEWROUTE, "RTM_NEWROUTE"},
	{RTM_DELROUTE, "RTM_DELROUTE"},
	{RTM_GETROUTE, "RTM_GETROUTE"},
	{RTM_NEWLINK,  "RTM_NEWLINK"},
	{RTM_DELLINK,  "RTM_DELLINK"},
	{RTM_GETLINK,  "RTM_GETLINK"},
	{RTM_NEWADDR,  "RTM_NEWADDR"},
	{RTM_DELADDR,  "RTM_DELADDR"},
	{RTM_GETADDR,  "RTM_GETADDR"},
	{0,            NULL}
};

static const struct message rtable_str[] = {
	{RT_TABLE_UNSPEC,   "unspecified"},
	{RT_TABLE_COMPAT,   "compat"},
	{RT_TABLE_DEFAULT,  "default"},
	{RT_TABLE_MAIN,     "main"},
	{RT_TABLE_LOCAL,    "local"},
	{RT_TABLE_MAX,      "all"},
	{0,                 NULL}
};

static const struct message rtproto_str[] = {
	{RTPROT_REDIRECT, "redirect"},
	{RTPROT_KERNEL,   "kernel"},
	{RTPROT_BOOT,     "boot"},
	{RTPROT_STATIC,   "static"},
	{RTPROT_GATED,    "GateD"},
	{RTPROT_RA,       "router advertisement"},
	{RTPROT_MRT,      "MRT"},
	{RTPROT_ZEBRA,    "Zebra"},
#ifdef RTPROT_BIRD
	{RTPROT_BIRD,     "BIRD"},
#endif /* RTPROT_BIRD */
	{RTPROT_RIP,      "rip"},
	{RTPROT_RIPNG,    "ripng"},
	{RTPROT_OSPF,     "ospf"},
	{RTPROT_OSPF6,    "ospfv3"},
	{RTPROT_BGP,      "bgp4/4+"},
	{0,               NULL}
};

static const struct message rtype_str[] = {
	{RTN_UNSPEC,       "unspecified"},
	{RTN_UNICAST,      "unicast"},
	{RTN_LOCAL,        "host"},
	{RTN_BROADCAST,    "broadcast"},
	{RTN_ANYCAST,      "anycast"},
	{RTN_MULTICAST,    "multicast"},
	{RTN_BLACKHOLE,    "blackhole"},
	{RTN_UNREACHABLE,  "unreachable"},
	{RTN_PROHIBIT,     "prohibit"},
	{RTN_THROW,        "throw"},
	{RTN_NAT,          "nat"},
	{RTN_XRESOLVE,     "xresolve"},
	{0,                NULL}
};

static const struct message rscope_str[] = {
	{RT_SCOPE_UNIVERSE,    "global"},
	{RT_SCOPE_SITE,        "AS local"},
	{RT_SCOPE_LINK,        "link local"},
	{RT_SCOPE_HOST,        "host local"},
	{RT_SCOPE_NOWHERE,     "nowhere"},
	{0,                    NULL}
};

/* Message lookup function. */
static const char *lookup(const struct message *mes, int key)
{
	const struct message *pnt;

	for (pnt = mes; pnt->str; pnt++)
		if (pnt->key == key)
			return pnt->str;

	return "unknown";
}

/* Wrapper around strerror to handle case where it returns NULL. */
const char *safe_strerror(int errnum)
{
	const char *s = strerror(errnum);
	return (s != NULL) ? s : "Unknown error";
}

/* Make socket for Linux netlink interface. */
static int netlink_socket (struct nlsock *nl, unsigned long groups)
{
	int ret;
	struct sockaddr_nl snl;
	int sock;
	int namelen;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		printf("Can't open %s socket: %s\n", nl->name, safe_strerror(errno));
		return -1;
	}

	memset (&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;
	snl.nl_groups = groups;

	/* Bind the socket to the netlink structure for anything. */
	ret = bind(sock, (struct sockaddr *)&snl, sizeof(snl));
	if (ret < 0) {
		printf("Can't bind %s socket to group 0x%x: %s\n",
				nl->name, snl.nl_groups, safe_strerror(errno));
		close (sock);
		return -1;
	}

	/* multiple netlink sockets will have different nl_pid */
	namelen = sizeof(snl);
	ret = getsockname(sock, (struct sockaddr *)&snl, (socklen_t *)&namelen);
	if (ret < 0 || namelen != sizeof(snl)) {
		printf("Can't get %s socket name: %s\n", nl->name, safe_strerror(errno));
		close (sock);
		return -1;
	}

	nl->snl = snl;
	nl->sock = sock;
	return ret;
}


#ifndef HAVE_NETLINK
#define HAVE_NETLINK
/* Receive buffer size for netlink socket */
u_int32_t nl_rcvbufsize = 4194304;
#endif /* HAVE_NETLINK */

#ifndef SO_RCVBUFFORCE
#define SO_RCVBUFFORCE  (33)
#endif

static int netlink_recvbuf(struct nlsock *nl, uint32_t newsize)
{
	u_int32_t oldsize;
	socklen_t newlen = sizeof(newsize);
	socklen_t oldlen = sizeof(oldsize);
	int ret;

	ret = getsockopt(nl->sock, SOL_SOCKET, SO_RCVBUF, &oldsize, &oldlen);
	if (ret < 0) {
		printf("Can't get %s receive buffer size: %s\n", nl->name,
		safe_strerror (errno));
		return -1;
	}

	/* Try force option (linux >= 2.6.14) and fall back to normal set */
	ret = setsockopt(nl->sock, SOL_SOCKET, SO_RCVBUFFORCE, &nl_rcvbufsize,
			sizeof(nl_rcvbufsize));
	if (ret < 0) {
		ret = setsockopt(nl->sock, SOL_SOCKET, SO_RCVBUF, &nl_rcvbufsize,
				sizeof(nl_rcvbufsize));
		if (ret < 0) {
			printf("Can't set %s receive buffer size: %s\n", nl->name,
				safe_strerror (errno));
			return -1;
		}
	}

	ret = getsockopt(nl->sock, SOL_SOCKET, SO_RCVBUF, &newsize, &newlen);
	if (ret < 0) {
		printf("Can't get %s receive buffer size: %s\n", nl->name,
			safe_strerror (errno));
		return -1;
	}

	printf("Setting netlink socket receive buffer size: %u -> %u\n",
		oldsize, newsize);

	return 0;
}

void kernel_init (void)
{
	unsigned long groups;

	groups = RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR |
		RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR;
	netlink_socket (&netlink, groups);

	/* Register kernel socket. */
	if (netlink.sock > 0) {
#if 0
		/* Only want non-blocking on the netlink event socket */
		if (fcntl (netlink.sock, F_SETFL, O_NONBLOCK) < 0)
			printf("Can't set %s socket flags: %s\n",
				netlink.name, safe_strerror(errno));
#endif
		/* Set receive buffer size if it's set from command line */
		if (nl_rcvbufsize)
			netlink_recvbuf (&netlink, nl_rcvbufsize);
	}
}

static int is_valid_kernel_table(u_int32_t table_id)
{
	if ((table_id == RT_TABLE_MAIN) ||
		(table_id == RT_TABLE_LOCAL) ||
		(table_id == RT_TABLE_COMPAT) ||
		(table_id > RT_TABLE_UNSPEC))
		return 1;
	else
		return 0;
}


/* Utility function for parse rtattr. */
static void netlink_parse_rtattr (struct rtattr **tb, int max,
	struct rtattr *rta, int len)
{
	while (RTA_OK (rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT (rta, len);
	}
}

/* Routing information change from the kernel. */
static int netlink_route_change(struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	int len;
	struct rtmsg *rtm;
	struct rtattr *tb[RTA_MAX + 1];
	char anyaddr[16] = {0};
	//char straddr[INET6_ADDRSTRLEN];
	char if_name[IFNAMSIZ];

	int index;
	int table;
	int metric;

	void *dest;
	void *gate;
	void *src;

	rtm = NLMSG_DATA(h);

	if (h->nlmsg_type != RTM_NEWROUTE && h->nlmsg_type != RTM_DELROUTE) {
		/* If this is not route add/delete message print warning. */
		printf("Kernel message: %d\n", h->nlmsg_type);
		return 0;
	}

	if (rtm->rtm_flags & RTM_F_CLONED) {
		//printf("This route is cloned from another route!\n");
		return 0;
	}

	printf("nlmsg: %s, family: %s, rtable: %d-%s, rtype: %d-%s, rtproto: %d-%s\n",
	       lookup(nlmsg_str, h->nlmsg_type),
	       rtm->rtm_family == AF_INET ? "ipv4" : "ipv6",
	       rtm->rtm_table, lookup(rtable_str, rtm->rtm_table),
	       rtm->rtm_type, lookup(rtype_str, rtm->rtm_type),
	       rtm->rtm_protocol, lookup(rtproto_str, rtm->rtm_protocol));

	table = rtm->rtm_table;
	if (!is_valid_kernel_table(table)) {
		printf("invalid kernel table: %d\n", table);
		return 0;
	}

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));
	if (len < 0) {
		printf("netlink msg length error!\n");
		return -1;
	}

	memset(tb, 0, sizeof tb);
	netlink_parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), len);

	if (rtm->rtm_src_len != 0) {
		printf("netlink_route_change(): no src len\n");
		return 0;
	}

	index = 0;
	metric = 0;
	dest = NULL;
	gate = NULL;
	src = NULL;

	if (tb[RTA_OIF])
		index = *(int *)RTA_DATA(tb[RTA_OIF]);

	if (tb[RTA_DST])
		dest = RTA_DATA(tb[RTA_DST]);
	else
		dest = anyaddr;

	if (tb[RTA_GATEWAY])
		gate = RTA_DATA(tb[RTA_GATEWAY]);

	if (tb[RTA_PREFSRC])
		src = RTA_DATA(tb[RTA_PREFSRC]);

	if (h->nlmsg_type == RTM_NEWROUTE && tb[RTA_PRIORITY])
		metric = *(int *)RTA_DATA(tb[RTA_PRIORITY]);

	if (rtm->rtm_family == AF_INET) {
		struct prefix_ipv4 p;
		p.family = AF_INET;
		memcpy (&p.prefix, dest, 4);
		p.prefixlen = rtm->rtm_dst_len;

		//inet_ntop(p->family, &p->u.prefix, straddr, INET6_ADDRSTRLEN);

		if (h->nlmsg_type == RTM_NEWROUTE)
			printf("\tadd route %s/%d\n",
				inet_ntoa(p.prefix), p.prefixlen);
		else
			printf("\tdel route %s/%d\n",
				inet_ntoa(p.prefix), p.prefixlen);

		if (!tb[RTA_MULTIPATH]) {
			if (gate) {
				if (index)
					printf("\t\tnexthop via %s dev %s\n",
						inet_ntoa(*(struct in_addr *)gate),
						if_index2name(index, if_name));
				else
					printf("\t\tnexthop via %s\n",
						inet_ntoa(*(struct in_addr *)gate));

			} else {
				if (index)
					printf("\t\tdev %s\n",
						if_index2name(index, if_name));
			}
		} else {
			/* This is a multipath route */
			struct rtnexthop *rtnh =
				(struct rtnexthop *)RTA_DATA(tb[RTA_MULTIPATH]);

			len = RTA_PAYLOAD (tb[RTA_MULTIPATH]);
			for (;;) {
				if (len < (int)sizeof(*rtnh) || rtnh->rtnh_len > len)
					break;

				index = rtnh->rtnh_ifindex;
				gate = 0;
				if (rtnh->rtnh_len > sizeof (*rtnh)) {
					memset (tb, 0, sizeof(tb));
					netlink_parse_rtattr (tb, RTA_MAX, RTNH_DATA(rtnh),
						rtnh->rtnh_len - sizeof(*rtnh));
					if (tb[RTA_GATEWAY])
						gate = RTA_DATA(tb[RTA_GATEWAY]);
				}

				if (gate) {
					if (index)
						printf("\t\tnexthop via %s dev %s\n",
							inet_ntoa(*(struct in_addr *)gate),
							if_index2name(index, if_name));
					else
						printf("\t\tnexthop via %s\n",
							inet_ntoa(*(struct in_addr *)gate));
				} else {
					if (index)
						printf("\t\tdev %s\n",
							if_index2name(index, if_name));
				}
				len -= NLMSG_ALIGN(rtnh->rtnh_len);
				rtnh = RTNH_NEXT(rtnh);
			}
		}
	}

#ifdef HAVE_IPV6
	if (rtm->rtm_family == AF_INET6) {
		struct prefix_ipv6 p;
		char buf[BUFSIZ];

		p.family = AF_INET6;
		memcpy (&p.prefix, dest, 16);
		p.prefixlen = rtm->rtm_dst_len;

		if (h->nlmsg_type == RTM_NEWROUTE)
			printf("\tadd route %s/%d\n",
				inet_ntop(AF_INET6, &p.prefix, buf, BUFSIZ),
				p.prefixlen);
		else
			printf("\tdel route %s/%d\n",
				inet_ntop(AF_INET6, &p.prefix, buf, BUFSIZ),
				p.prefixlen);

		/* FIXME: add multipath process. */
		if (h->nlmsg_type == RTM_NEWROUTE) {
			if (gate) {
				if (index)
					printf("\t\tnexthop via %s dev %s\n",
						inet_ntop(AF_INET6, gate, buf, INET6_ADDRSTRLEN),
						if_index2name(index, if_name));
				else
					printf("\t\tnexthop via %s\n",
						 inet_ntop(AF_INET6, gate, buf, INET6_ADDRSTRLEN));
			} else {
				printf("\t\tdev %s\n", if_index2name(index, if_name));
			}
		} else {
			if (gate)
				printf("\t\tnexthop via %s",
					inet_ntop(AF_INET6, gate, buf, INET6_ADDRSTRLEN));
			if (index)
				printf(" dev %s", if_index2name(index, if_name));
			if (gate || index)
				printf("\n");
		}
	}
#endif /* HAVE_IPV6 */

	printf("\n");

	return 0;
}

/* Utility function to parse hardware link-layer address */
static void netlink_interface_get_hw_addr(struct rtattr **tb,
	u_char hw_addr[], int *hw_addr_len)
{
	int i;

	if (tb[IFLA_ADDRESS]) {
		int __hw_addr_len;

		__hw_addr_len = RTA_PAYLOAD(tb[IFLA_ADDRESS]);

		if (__hw_addr_len > IF_HWADDR_MAX) {
			printf("Hardware address is too large: %d\n", __hw_addr_len);
		} else {
			*hw_addr_len = __hw_addr_len;
			memcpy(hw_addr, RTA_DATA(tb[IFLA_ADDRESS]), __hw_addr_len);

			for (i = 0; i < __hw_addr_len; i++)
				if (hw_addr[i] != 0)
					break;

			if (i == __hw_addr_len)
				*hw_addr_len = 0;
			else
				*hw_addr_len = __hw_addr_len;
		}
	}
}

static int netlink_link_change (struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	int len;
	unsigned int index;
	struct ifinfomsg *ifi;
	struct rtattr *tb[IFLA_MAX + 1];
	char *name;

	ifi = NLMSG_DATA (h);

	if (!(h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK)) {
		/* If this is not link add/delete message so print warning. */
		printf("netlink_link_change: wrong kernel message %d\n",
			h->nlmsg_type);
		return 0;
	}

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
	if (len < 0)
		return -1;

	/* Looking up interface name. */
	memset (tb, 0, sizeof tb);
	netlink_parse_rtattr (tb, IFLA_MAX, IFLA_RTA(ifi), len);

#ifdef IFLA_WIRELESS
	/* check for wireless messages to ignore */
	if ((tb[IFLA_WIRELESS] != NULL) && (ifi->ifi_change == 0)) {
		printf("%s: ignoring IFLA_WIRELESS message\n", __func__);
		return 0;
	}
#endif /* IFLA_WIRELESS */

	if (tb[IFLA_IFNAME] == NULL)
		return -1;
	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);

	/* Add interface. */
	if (h->nlmsg_type == RTM_NEWLINK) {
		u_char hw_addr[IF_HWADDR_MAX];
		int hw_addr_len;

		index = if_name2index(name);
		if (0 == index) {
			printf("add link dev %s index %d", name, ifi->ifi_index);
		} else {
			/* Interface status change. */
			printf("update link dev %s index %d", name, ifi->ifi_index);
		}

		netlink_interface_get_hw_addr(tb, hw_addr, &hw_addr_len);

		int i;
		for (i = 0; i < hw_addr_len; i++)
			printf("%s%02x", i == 0 ? "" : ":", hw_addr[i]);

		printf(" mtu %d flags %d\n",
			*(int *)RTA_DATA(tb[IFLA_MTU]), ifi->ifi_flags & 0x0000fffff);
	}else {
		/* RTM_DELLINK. */
		index = if_name2index(name);
		if (0 == index)
			printf("interface %s is deleted but can't find\n", name);
		else
			printf("delete link dev %s index %d\n",
				name, ifi->ifi_index);
	}

	return 0;
}

/* Lookup interface IPv4/IPv6 address. */
static int netlink_interface_addr(struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	int len;
	struct ifaddrmsg *ifa;
	struct rtattr *tb[IFA_MAX + 1];
	char name[IFNAMSIZ];
	char *if_name;
	char buf[BUFSIZ];

	ifa = NLMSG_DATA (h);

	if (ifa->ifa_family != AF_INET
#ifdef HAVE_IPV6
	&& ifa->ifa_family != AF_INET6
#endif /* HAVE_IPV6 */
	)
	return 0;

	if (h->nlmsg_type != RTM_NEWADDR && h->nlmsg_type != RTM_DELADDR)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	if (len < 0)
		return -1;

	memset (tb, 0, sizeof tb);
	netlink_parse_rtattr (tb, IFA_MAX, IFA_RTA(ifa), len);

  	if_name = if_index2name(ifa->ifa_index, name);
  	if (!if_name || if_name[0] == '\0') {
		printf("netlink_interface_addr can't find interface by index %d\n",
			ifa->ifa_index);
		return -1;
	}

	printf("nlmsg: %s, family: %s, %s on dev %s\n",
	       lookup(nlmsg_str, h->nlmsg_type), ifa->ifa_family == AF_INET ? "ipv4" : "ipv6",
	       (h->nlmsg_type == RTM_NEWADDR) ? "add addr" : "del addr", if_name);

	if (tb[IFA_LOCAL])
		printf("\t  IFA_LOCAL     %s/%d\n",
			inet_ntop (ifa->ifa_family, RTA_DATA(tb[IFA_LOCAL]),
				buf, BUFSIZ), ifa->ifa_prefixlen);
	if (tb[IFA_ADDRESS])
		printf("\t  IFA_ADDRESS   %s/%d\n",
			inet_ntop(ifa->ifa_family, RTA_DATA (tb[IFA_ADDRESS]),
				buf, BUFSIZ), ifa->ifa_prefixlen);
	if (tb[IFA_BROADCAST])
		printf("\t  IFA_BROADCAST %s/%d\n",
			inet_ntop(ifa->ifa_family, RTA_DATA(tb[IFA_BROADCAST]),
				buf, BUFSIZ), ifa->ifa_prefixlen);
	if (tb[IFA_LABEL] && strcmp (if_name, RTA_DATA(tb[IFA_LABEL])))
		printf("\t  IFA_LABEL     %s\n", (char *)RTA_DATA(tb[IFA_LABEL]));

	if (tb[IFA_CACHEINFO]) {
		struct ifa_cacheinfo *ci = RTA_DATA(tb[IFA_CACHEINFO]);
		printf("\t  IFA_CACHEINFO pref %d, valid %d\n",
			ci->ifa_prefered, ci->ifa_valid);
	}

	printf("\n");

	return 0;
}

static int netlink_information_fetch(struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	/* Ignore messages that aren't from the kernel */
	if (snl->nl_pid != 0)	{
		printf("Ignoring message from pid %u that isn't from the kernel!\n",
			snl->nl_pid);
		return 0;
	}

	switch (h->nlmsg_type) {
	case RTM_NEWROUTE:
		return netlink_route_change(snl, h);
		break;
	case RTM_DELROUTE:
		return netlink_route_change(snl, h);
		break;
	case RTM_NEWLINK:
		return netlink_link_change(snl, h);
		break;
	case RTM_DELLINK:
		return netlink_link_change(snl, h);
		break;
	case RTM_NEWADDR:
		return netlink_interface_addr(snl, h);
		break;
	case RTM_DELADDR:
		return netlink_interface_addr(snl, h);
		break;
	default:
		printf("Unknown netlink nlmsg_type %d\n", h->nlmsg_type);
		break;
	}
	return 0;
}


#define NL_PKT_BUF_SIZE         8192

/* Hack for GNU libc version 2. */
#ifndef MSG_TRUNC
#define MSG_TRUNC      0x20
#endif /* MSG_TRUNC */

/* Receive message from netlink interface and pass those information
 * to the given function.
 */
static int netlink_parse_info (int (*filter)(struct sockaddr_nl *, struct nlmsghdr *),
	struct nlsock *nl)
{
	int status;
	int ret = 0;
	int error;

	while (1) {
		char buf[NL_PKT_BUF_SIZE];
		struct iovec iov = {
			.iov_base = buf,
			.iov_len = sizeof(buf)
		};
		struct sockaddr_nl snl;
		struct msghdr msg = {
			.msg_name = (void *)&snl,
			.msg_namelen = sizeof(snl),
			.msg_iov = &iov,
			.msg_iovlen = 1
		};
		struct nlmsghdr *h;

		status = recvmsg(nl->sock, &msg, 0);
		if (status < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;
			printf("%s recvmsg overrun: %s\n",
				nl->name, safe_strerror(errno));
			continue;
		}

		if (status == 0) {
			printf("%s EOF\n", nl->name);
			return -1;
		}

		if (msg.msg_namelen != sizeof(snl)){
			printf("%s sender address length error: length %d\n",
				nl->name, msg.msg_namelen);
			return -1;
		}

		for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned int)status);
			h = NLMSG_NEXT(h, status)) {
			/* Finish of reading. */
			if (h->nlmsg_type == NLMSG_DONE)
				return ret;

			/* Error handling. */
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
				int errnum = err->error;
				int msg_type = err->msg.nlmsg_type;

				/* If the error field is zero, then this is an ACK */
				if (err->error == 0) {
#if 0
					printf("%s: %s ACK: type=%s(%u), seq=%u, pid=%u\n",
						__FUNCTION__, nl->name,
						lookup (nlmsg_str, err->msg.nlmsg_type),
						err->msg.nlmsg_type, err->msg.nlmsg_seq,
						err->msg.nlmsg_pid);
#endif
					/* return if not a multipart message, otherwise continue */
					if (!(h->nlmsg_flags & NLM_F_MULTI)) {
						return 0;
					}
					continue;
				}

				if (h->nlmsg_len < NLMSG_LENGTH (sizeof (struct nlmsgerr))) {
					printf("%s error: message truncated\n", nl->name);
					return -1;
				}

				printf("%s error: %s, type=%s(%u), seq=%u, pid=%u\n",
					nl->name, safe_strerror(-errnum),
					lookup (nlmsg_str, msg_type),
					msg_type, err->msg.nlmsg_seq, err->msg.nlmsg_pid);

				return -1;
			}
#if 0

			/* OK we got netlink message. */
			printf("netlink_parse_info: %s type %s(%u), seq=%u, pid=%u\n",
				nl->name,
				lookup (nlmsg_str, h->nlmsg_type), h->nlmsg_type,
				h->nlmsg_seq, h->nlmsg_pid);
#endif

			error = (*filter)(&snl, h);
			if (error < 0) {
				printf("%s filter function error\n", nl->name);
				ret = error;
			}
		}

		/* After error care. */
		if (msg.msg_flags & MSG_TRUNC) {
			printf("%s error: message truncated\n", nl->name);
			continue;
		}
		if (status) {
			printf("%s error: data remnant size %d\n", nl->name, status);
			return -1;
		}
	}

	return ret;
}

int main(int argc, char *agrv[])
{
	kernel_init();

	netlink_parse_info(netlink_information_fetch, &netlink);

	return 0;
}

