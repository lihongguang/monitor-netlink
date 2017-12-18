#ifndef _RT_NETLINK_H_
#define _RT_NETLINK_H_

#ifndef HAVE_U_CHAR
typedef unsigned char u_char;
#define HAVE_U_CHAR
#endif /* HAVE_U_CHAR */

#ifndef DOCKER_LINUX
#define DOCKER_LINUX
#endif

#ifdef FRR
#define RTPROT_BGP        186
#define RTPROT_ISIS       187
#define RTPROT_OSPF       188
#define RTPROT_RIP        189
#define RTPROT_RIPNG      190
#if !defined(RTPROT_BABEL)
#define RTPROT_BABEL      42
#endif
#define RTPROT_NHRP       191
#define RTPROT_EIGRP      192
#define RTPROT_LDP        193
#elif defined(DOCKER_LINUX)
#define RTPROT_RIP        250
#define RTPROT_RIPNG	  251
#define RTPROT_OSPF       252
#define RTPROT_OSPF6      253
#define RTPROT_BGP        254
#endif

#define IF_NAMSIZ         20
#define IF_HWADDR_MAX     20

/* Message structure. */
struct message
{
	int key;
	const char *str;
};

static inline char *if_index2name(int index, char *name)
{
	char *if_name = if_indextoname(index, name);
	if (name == NULL && errno == ENXIO)
		return "";
	else
		return if_name;
}

static inline unsigned int if_name2index(char *name)
{
	return if_nametoindex(name);
}

#endif
