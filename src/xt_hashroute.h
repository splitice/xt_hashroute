#ifndef _UAPI_XT_HASHROUTE_H
#define _UAPI_XT_HASHROUTE_H

#include <linux/types.h>
#include <linux/if.h>

/* packet length accounting is done in 16-byte steps */
#define XT_HASHROUTE_BYTE_SHIFT 4

/* details of this structure hidden by the implementation */
struct xt_hashroute_htable;

enum {
	XT_HASHROUTE_HASH_DIP = 1 << 0,
	XT_HASHROUTE_HASH_DPT = 1 << 1,
	XT_HASHROUTE_HASH_SIP = 1 << 2,
	XT_HASHROUTE_HASH_SPT = 1 << 3,
	XT_HASHROUTE_INVERT   = 1 << 4,
	XT_HASHROUTE_MATCH_ONLY   = 1 << 5,
};

struct hashroute_cfg  {
	 __u32 mode;       /* bitmask of XT_HASHLIMIT_HASH_* */
	int value;
	
	/* user specified */
	__u32 size;		/* how many buckets */
	__u32 max;		/* max number of entries */
	__u32 gc_interval;	/* gc interval */
	__u32 expire;	/* when do entries expire? */
	
	__u8 srcmask, dstmask;
};

struct xt_hashroute_mtinfo {
	char name [IFNAMSIZ];		/* name */
	struct hashroute_cfg cfg;

	/* Used internally by the kernel */
	struct xt_hashroute_htable *hinfo;
	union {
		void *ptr;
		struct xt_hashroute_info *master;
	} u;
};

#endif /* _UAPI_XT_HASHROUTE_H */