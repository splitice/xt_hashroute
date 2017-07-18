/*
 *	xt_hashroute - Netfilter module to return traffic to the originating interface & mac
 *  based off a hash (sourceip/sourceport/dstip/dstport)
 *
 *	(C) 2016 - : Mathew Heard, X4B
 *
 * Development of this code was funded by X4B DDoS Protection <https://www.x4b.net>
 * 
 * Code derived from xt_hashlimit.
 */
//#define DEBUG 1
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/mm.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/netfilter/nf_conntrack.h>
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
#include <linux/ipv6.h>
#include <net/ipv6.h>
#endif

#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include "xt_hashroute.h"
#include <linux/mutex.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mathew Heard <mheard@x4b.net>");
MODULE_DESCRIPTION("Xtables: per hash-bucket interface return match");
MODULE_ALIAS("ipt_hashroute");
MODULE_ALIAS("ip6t_hashroute");
MODULE_ALIAS("xt_HASHROUTE");
MODULE_ALIAS("ipt_HASHROUTE");
MODULE_ALIAS("ip6t_HASHROUTE");

struct hashroute_net {
	struct hlist_head	htables;
	struct proc_dir_entry	*ipt_hashroute;
	struct proc_dir_entry	*ip6t_hashroute;
};

static unsigned int hashroute_net_id;
static inline struct hashroute_net *hashroute_pernet(struct net *net)
{
	return net_generic(net, hashroute_net_id);
}

/* need to declare this at the top */
static const struct file_operations dl_file_ops_v1;
static const struct file_operations dl_file_ops;

/* hash table crap */
struct dsthash_dst {
	union {
		struct {
			__be32 src;
			__be32 dst;
		} ip;
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
		struct {
			__be32 src[4];
			__be32 dst[4];
		} ip6;
#endif
	};
	__be16 src_port;
	__be16 dst_port;
};

struct dsthash_ent {
	/* static / read-only parts in the beginning */
	struct hlist_node node;
	struct dsthash_dst dst;

	/* modified structure members in the end */
	spinlock_t lock;
	unsigned long expires;		/* precalculated expiry time */	
	struct net_device * dev;
	char header[8];
	struct rcu_head rcu;
};

struct xt_hashroute_htable {
	struct hlist_node node;		/* global list of all htables */
	int use;
	u_int8_t family;
	bool rnd_initialized;

	struct hashroute_cfg cfg;	/* config */

	/* used internally */
	spinlock_t lock;		/* lock for list_head */
	u_int32_t rnd;			/* random seed for hash */
	unsigned int count;		/* number entries in table */
	struct delayed_work gc_work;

	/* seq_file stuff */
	struct proc_dir_entry *pde;
	const char *name;
	struct net *net;

	struct hlist_head hash[0];	/* hashtable itself */
};

static int
cfg_copy(struct hashroute_cfg *to, void *from, int revision)
{
	memcpy(to, from, sizeof(struct hashroute_cfg));

	return 0;
}

static DEFINE_MUTEX(hashroute_mutex);	/* protects htables list */
static struct kmem_cache *hashroute_cachep __read_mostly;

static inline bool dst_cmp(const struct dsthash_ent *ent,
			   const struct dsthash_dst *b)
{
	return !memcmp(&ent->dst, b, sizeof(ent->dst));
}

static u_int32_t
hash_dst(const struct xt_hashroute_htable *ht, const struct dsthash_dst *dst)
{
	u_int32_t hash = jhash2((const u32 *)dst,
				sizeof(*dst)/sizeof(u32),
				ht->rnd);
	/*
	 * Instead of returning hash % ht->cfg.size (implying a divide)
	 * we return the high 32 bits of the (hash * ht->cfg.size) that will
	 * give results between [0 and cfg.size-1] and same hash distribution,
	 * but using a multiply, less expensive than a divide
	 */
	return reciprocal_scale(hash, ht->cfg.size);
}

static struct dsthash_ent *
dsthash_find(const struct xt_hashroute_htable *ht,
	     const struct dsthash_dst *dst)
{
	struct dsthash_ent *ent;
	u_int32_t hash = hash_dst(ht, dst);

	if (!hlist_empty(&ht->hash[hash])) {
		hlist_for_each_entry_rcu(ent, &ht->hash[hash], node)
			if (dst_cmp(ent, dst)) {
				spin_lock(&ent->lock);
				return ent;
			}
	}
	return NULL;
}

/* allocate dsthash_ent, initialize dst, put in htable and lock it */
static struct dsthash_ent *
dsthash_alloc_init(struct xt_hashroute_htable *ht,
		   const struct dsthash_dst *dst)
{
	struct dsthash_ent *ent;

	spin_lock(&ht->lock);

	/* Two or more packets may race to create the same entry in the
	 * hashtable, double check if this packet lost race.
	 */
	ent = dsthash_find(ht, dst);
	if (ent != NULL) {
		spin_unlock(&ht->lock);
		spin_lock(&ent->lock);
		return ent;
	}

	/* initialize hash with random val at the time we allocate
	 * the first hashtable entry */
	if (unlikely(!ht->rnd_initialized)) {
		get_random_bytes(&ht->rnd, sizeof(ht->rnd));
		ht->rnd_initialized = true;
	}

	if (ht->cfg.max && ht->count >= ht->cfg.max) {
		/* FIXME: do something. question is what.. */
		net_err_ratelimited("max count of %u reached\n", ht->cfg.max);
		ent = NULL;
	} else {
		ent = kmem_cache_alloc(hashroute_cachep, GFP_ATOMIC);
		memcpy(&ent->dst, dst, sizeof(ent->dst));
		ent->dev = NULL;
		spin_lock_init(&ent->lock);

		spin_lock(&ent->lock);
		hlist_add_head_rcu(&ent->node, &ht->hash[hash_dst(ht, dst)]);
		ht->count++;
	}
	spin_unlock(&ht->lock);
	return ent;
}

static void dsthash_free_rcu(struct rcu_head *head)
{
	struct dsthash_ent *ent = container_of(head, struct dsthash_ent, rcu);

	kmem_cache_free(hashroute_cachep, ent);
}

static inline void
dsthash_free_entry(struct xt_hashroute_htable *ht, struct dsthash_ent *ent)
{
	hlist_del_rcu(&ent->node);
	call_rcu(&ent->rcu, dsthash_free_rcu);
	ht->count--;
}

static inline void
dsthash_free_entry_bh(struct xt_hashroute_htable *ht, struct dsthash_ent *ent)
{
	hlist_del_rcu(&ent->node);
	call_rcu_bh(&ent->rcu, dsthash_free_rcu);
	ht->count--;
}

static inline void
dsthash_free(struct xt_hashroute_htable *ht, struct dsthash_ent *ent)
{
	spin_lock_bh(&ent->lock);
	if(ent->dev != NULL){
		dev_put(ent->dev);
		ent->dev = NULL;
	}
	spin_unlock_bh(&ent->lock);
	
	dsthash_free_entry(ht, ent);
}
static void htable_gc(struct work_struct *work);

static int htable_create(struct net *net, struct hashroute_cfg *cfg,
			 const char *name, u_int8_t family,
			 struct xt_hashroute_htable **out_hinfo,
			 int revision)
{
	struct hashroute_net *hashroute_net = hashroute_pernet(net);
	struct xt_hashroute_htable *hinfo;
	unsigned int size, i;
	int ret;

	if (cfg->size) {
		size = cfg->size;
	} else {
		size = (totalram_pages << PAGE_SHIFT) / 16384 /
		       sizeof(struct list_head);
		if (totalram_pages > 1024 * 1024 * 1024 / PAGE_SIZE)
			size = 8192;
		if (size < 16)
			size = 16;
	}
	/* FIXME: don't use vmalloc() here or anywhere else -HW */
	hinfo = vmalloc(sizeof(struct xt_hashroute_htable) +
	                sizeof(struct list_head) * size);
	if (hinfo == NULL)
		return -ENOMEM;
	*out_hinfo = hinfo;

	/* copy match config into hashtable config */
	ret = cfg_copy(&hinfo->cfg, (void *)cfg, 2);

	if (ret)
		return ret;

	hinfo->cfg.size = size;
	if (hinfo->cfg.max == 0)
		hinfo->cfg.max = 8 * hinfo->cfg.size;
	else if (hinfo->cfg.max < hinfo->cfg.size)
		hinfo->cfg.max = hinfo->cfg.size;

	for (i = 0; i < hinfo->cfg.size; i++)
		INIT_HLIST_HEAD(&hinfo->hash[i]);

	hinfo->use = 1;
	hinfo->count = 0;
	hinfo->family = family;
	hinfo->rnd_initialized = false;
	hinfo->name = kstrdup(name, GFP_KERNEL);
	if (!hinfo->name) {
		vfree(hinfo);
		return -ENOMEM;
	}
	spin_lock_init(&hinfo->lock);

	hinfo->pde = proc_create_data(name, 0,
		(family == NFPROTO_IPV4) ?
		hashroute_net->ipt_hashroute : hashroute_net->ip6t_hashroute,
		&dl_file_ops,
		hinfo);
	if (hinfo->pde == NULL) {
		kfree(hinfo->name);
		vfree(hinfo);
		return -ENOMEM;
	}
	hinfo->net = net;

	INIT_DEFERRABLE_WORK(&hinfo->gc_work, htable_gc);
	queue_delayed_work(system_power_efficient_wq, &hinfo->gc_work,
			   msecs_to_jiffies(hinfo->cfg.gc_interval));

	hlist_add_head(&hinfo->node, &hashroute_net->htables);

	return 0;
}

static bool select_all(const struct xt_hashroute_htable *ht,
		       const struct dsthash_ent *he)
{
	return 1;
}

static bool select_gc(const struct xt_hashroute_htable *ht,
		      const struct dsthash_ent *he)
{
	return (he->expires != 0 && time_after_eq(jiffies, he->expires)) || (he->dev != NULL && he->dev->reg_state==NETREG_UNREGISTERING);
}

static void htable_selective_cleanup(struct xt_hashroute_htable *ht,
			bool (*select)(const struct xt_hashroute_htable *ht,
				      const struct dsthash_ent *he))
{
	unsigned int i;

	for (i = 0; i < ht->cfg.size; i++) {
		struct dsthash_ent *dh;
		struct hlist_node *n;

		spin_lock_bh(&ht->lock);
		hlist_for_each_entry_safe(dh, n, &ht->hash[i], node) {
			if ((*select)(ht, dh))
				dsthash_free(ht, dh);
		}
		spin_unlock_bh(&ht->lock);
		cond_resched();
	}
}

static void htable_gc(struct work_struct *work)
{
	struct xt_hashroute_htable *ht;

	ht = container_of(work, struct xt_hashroute_htable, gc_work.work);

	htable_selective_cleanup(ht, select_gc);

	queue_delayed_work(system_power_efficient_wq,
			   &ht->gc_work, msecs_to_jiffies(ht->cfg.gc_interval));
}

static void htable_remove_proc_entry(struct xt_hashroute_htable *hinfo)
{
	struct hashroute_net *hashroute_net = hashroute_pernet(hinfo->net);
	struct proc_dir_entry *parent;

	if (hinfo->family == NFPROTO_IPV4)
		parent = hashroute_net->ipt_hashroute;
	else
		parent = hashroute_net->ip6t_hashroute;

	if (parent != NULL)
		remove_proc_entry(hinfo->name, parent);
}

static void htable_destroy(struct xt_hashroute_htable *hinfo)
{
	cancel_delayed_work_sync(&hinfo->gc_work);
	htable_remove_proc_entry(hinfo);
	htable_selective_cleanup(hinfo, select_all);
	kfree(hinfo->name);
	vfree(hinfo);
}

static struct xt_hashroute_htable *htable_find_get(struct net *net,
						   const char *name,
						   u_int8_t family)
{
	struct hashroute_net *hashroute_net = hashroute_pernet(net);
	struct xt_hashroute_htable *hinfo;

	hlist_for_each_entry(hinfo, &hashroute_net->htables, node) {
		if (!strcmp(name, hinfo->name) &&
		    hinfo->family == family) {
			hinfo->use++;
			return hinfo;
		}
	}
	return NULL;
}

static void htable_put(struct xt_hashroute_htable *hinfo)
{
	mutex_lock(&hashroute_mutex);
	if (--hinfo->use == 0) {
		hlist_del(&hinfo->node);
		htable_destroy(hinfo);
	}
	mutex_unlock(&hashroute_mutex);
}

/* The algorithm used is the Simple Token Bucket Filter (TBF)
 * see net/sched/sch_tbf.c in the linux source tree
 */

/* Repeated shift and or gives us all 1s, final shift and add 1 gives
 * us the power of 2 below the theoretical max, so GCC simply does a
 * shift. */
#define _POW2_BELOW2(x) ((x)|((x)>>1))
#define _POW2_BELOW4(x) (_POW2_BELOW2(x)|_POW2_BELOW2((x)>>2))
#define _POW2_BELOW8(x) (_POW2_BELOW4(x)|_POW2_BELOW4((x)>>4))
#define _POW2_BELOW16(x) (_POW2_BELOW8(x)|_POW2_BELOW8((x)>>8))
#define _POW2_BELOW32(x) (_POW2_BELOW16(x)|_POW2_BELOW16((x)>>16))
#define _POW2_BELOW64(x) (_POW2_BELOW32(x)|_POW2_BELOW32((x)>>32))
#define POW2_BELOW32(x) ((_POW2_BELOW32(x)>>1) + 1)
#define POW2_BELOW64(x) ((_POW2_BELOW64(x)>>1) + 1)

static inline __be32 maskl(__be32 a, unsigned int l)
{
	return l ? htonl(ntohl(a) & ~0 << (32 - l)) : 0;
}

#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
static void hashroute_ipv6_mask(__be32 *i, unsigned int p)
{
	switch (p) {
	case 0 ... 31:
		i[0] = maskl(i[0], p);
		i[1] = i[2] = i[3] = 0;
		break;
	case 32 ... 63:
		i[1] = maskl(i[1], p - 32);
		i[2] = i[3] = 0;
		break;
	case 64 ... 95:
		i[2] = maskl(i[2], p - 64);
		i[3] = 0;
		break;
	case 96 ... 127:
		i[3] = maskl(i[3], p - 96);
		break;
	case 128:
		break;
	}
}
#endif

static int
hashroute_init_dst(const struct xt_hashroute_htable *hinfo,
		   struct dsthash_dst *dst,
		   const struct sk_buff *skb, unsigned int protoff, __u8 is_target, __u32 mode)
{
	__be16 _ports[2], *ports;
	u8 nexthdr;
	int poff;

	memset(dst, 0, sizeof(*dst));

	switch (hinfo->family) {
	case NFPROTO_IPV4:
		if(is_target){
			if(mode & XT_HASHROUTE_HASH_DIP){
				dst->ip.src = maskl(ip_hdr(skb)->saddr,
			              hinfo->cfg.srcmask);
			} else if(mode & XT_HASHROUTE_HASH_SIP){
				dst->ip.src = maskl(ip_hdr(skb)->daddr,
			              hinfo->cfg.dstmask);
			}
		}else{
			if(mode & XT_HASHROUTE_HASH_DIP){
				dst->ip.src = maskl(ip_hdr(skb)->daddr,
			              hinfo->cfg.dstmask);
			} else if(mode & XT_HASHROUTE_HASH_SIP){
				dst->ip.src = maskl(ip_hdr(skb)->saddr,
			              hinfo->cfg.srcmask);
			}
		}
			
		if ((mode & XT_HASHROUTE_HASH_DIP && is_target) || (mode & XT_HASHROUTE_HASH_SIP && !is_target))
			dst->ip.src = maskl(ip_hdr(skb)->saddr,
			              hinfo->cfg.srcmask);

		if (!(mode &
		      (XT_HASHROUTE_HASH_DPT | XT_HASHROUTE_HASH_SPT)))
			return 0;
		nexthdr = ip_hdr(skb)->protocol;
		break;
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	case NFPROTO_IPV6:
	{
		__be16 frag_off;

		if ((mode & XT_HASHROUTE_HASH_DIP && !is_target) || (mode & XT_HASHROUTE_HASH_SIP && is_target)) {
			memcpy(&dst->ip6.src, &ipv6_hdr(skb)->daddr,
			       sizeof(dst->ip6.src));
			hashroute_ipv6_mask(dst->ip6.src, hinfo->cfg.dstmask);
		}
		if ((mode & XT_HASHROUTE_HASH_DIP && is_target) || (mode & XT_HASHROUTE_HASH_SIP && !is_target)) {
			memcpy(&dst->ip6.src, &ipv6_hdr(skb)->saddr,
			       sizeof(dst->ip6.src));
			hashroute_ipv6_mask(dst->ip6.src, hinfo->cfg.srcmask);
		}

		if (!(mode &
		      (XT_HASHROUTE_HASH_DPT | XT_HASHROUTE_HASH_SPT)))
			return 0;
		nexthdr = ipv6_hdr(skb)->nexthdr;
		protoff = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr), &nexthdr, &frag_off);
		if ((int)protoff < 0)
			return -1;
		break;
	}
#endif
	default:
		BUG();
		return 0;
	}

	poff = proto_ports_offset(nexthdr);
	if (poff >= 0) {
		ports = skb_header_pointer(skb, protoff + poff, sizeof(_ports),
					   &_ports);
	} else {
		_ports[0] = _ports[1] = 0;
		ports = _ports;
	}
	if (!ports)
		return -1;
	if (hinfo->cfg.mode & XT_HASHROUTE_HASH_SPT)
		dst->src_port = ports[0];
	if (hinfo->cfg.mode & XT_HASHROUTE_HASH_DPT)
		dst->dst_port = ports[1];
	return 0;
}

static void dh_set_value(struct dsthash_ent *ent, const struct sk_buff *skb){
	struct net_device* dev;
	
	dev = skb->dev;
	if(dev == NULL){
		pr_warn("skb dev null\n");
		return;
	}
	
	if(unlikely(dev->addr_len > sizeof(ent->header))){
		pr_warn("link layer header too big\n");
		return;
	}
		
	if(ent->dev != dev){
		if(ent->dev != NULL){
			dev_put(ent->dev);
		}
		
		dev_parse_header(skb, ent->header);
		ent->dev = dev;
		dev_hold(dev);
	}
	return;
}

static bool
hashroute_mt_common(const struct sk_buff *skb, struct xt_action_param *par,
		    struct xt_hashroute_htable *hinfo,
		    const struct hashroute_cfg *cfg)
{
	struct dsthash_ent *dh;
	struct dsthash_dst dst;
	bool retval = true;

	if (hashroute_init_dst(hinfo, &dst, skb, par->thoff, 0, cfg->mode) < 0){
		par->hotdrop = true;
		return false;
	}

	rcu_read_lock_bh();
	dh = dsthash_find(hinfo, &dst);
	if (dh == NULL) {
		if(cfg->mode & XT_HASHROUTE_MATCH_ONLY){
			retval = false;
			goto ret;
		}
		dh = dsthash_alloc_init(hinfo, &dst);
		if (unlikely(dh == NULL)) {
			pr_warn("hash collision or race");
			par->hotdrop = true;
			goto ret;
		}
	}
	
	dh_set_value(dh, skb);
	if(unlikely(dh->dev == NULL)){
		dh->expires = jiffies;
	}else{
		if(hinfo->cfg.expire == 0){
			dh->expires = 0;
		}else{
			dh->expires = jiffies + msecs_to_jiffies(hinfo->cfg.expire);
		}
	}
	
	spin_unlock(&dh->lock);
	
ret:
	rcu_read_unlock_bh();
	return retval;
}

static bool
hashroute_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_hashroute_mtinfo *info = par->matchinfo;
	struct xt_hashroute_htable *hinfo = info->hinfo;

	return hashroute_mt_common(skb, par, hinfo, &info->cfg);
}

static int hashroute_mt_check_common(const struct xt_mtchk_param *par,
				     struct xt_hashroute_htable **hinfo,
				     struct hashroute_cfg *cfg,
				     const char *name, int revision)
{
	struct net *net = par->net;
	int ret = 0;

	if (cfg->gc_interval == 0)
		return -EINVAL;
	if (par->family == NFPROTO_IPV4) {
		if (cfg->srcmask > 32 || cfg->dstmask > 32)
			return -EINVAL;
	} else {
		if (cfg->srcmask > 128 || cfg->dstmask > 128)
			return -EINVAL;
	}

	/* Check for overflow. */
	mutex_lock(&hashroute_mutex);
	*hinfo = htable_find_get(net, name, par->family);
	if (*hinfo == NULL) {
		ret = htable_create(net, cfg, name, par->family, hinfo, revision);
		if (ret >= 0) {
			ret = 0;
		}
	}
	
	mutex_unlock(&hashroute_mutex);
	return ret;
}

static int hashroute_mt_check(const struct xt_mtchk_param *par)
{
	struct xt_hashroute_mtinfo *info = par->matchinfo;

	if (info->name[sizeof(info->name) - 1] != '\0')
		return -EINVAL;

	return hashroute_mt_check_common(par, &info->hinfo, &info->cfg,
					 info->name, 0);
}

static void hashroute_mt_destroy(const struct xt_mtdtor_param *par)
{
	const struct xt_hashroute_mtinfo *info = par->matchinfo;

	htable_put(info->hinfo);
}

static struct xt_match hashroute_mt_reg[] __read_mostly = {
	{
		.name           = "hashroute",
		.revision       = 0,
		.family         = NFPROTO_IPV4,
		.match          = hashroute_mt,
		.matchsize      = sizeof(struct xt_hashroute_mtinfo),
		.checkentry     = hashroute_mt_check,
		.destroy        = hashroute_mt_destroy,
		.me             = THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	{
		.name           = "hashroute",
		.revision       = 0,
		.family         = NFPROTO_IPV6,
		.match          = hashroute_mt,
		.matchsize      = sizeof(struct xt_hashroute_mtinfo),
		.checkentry     = hashroute_mt_check,
		.destroy        = hashroute_mt_destroy,
		.me             = THIS_MODULE,
	},
#endif
};

/* PROC stuff */
static void *dl_seq_start(struct seq_file *s, loff_t *pos)
	__acquires(htable->lock)
{
	struct xt_hashroute_htable *htable = s->private;
	unsigned int *bucket;

	spin_lock_bh(&htable->lock);
	if (*pos >= htable->cfg.size)
		return NULL;

	bucket = kmalloc(sizeof(unsigned int), GFP_ATOMIC);
	if (!bucket)
		return ERR_PTR(-ENOMEM);

	*bucket = *pos;
	return bucket;
}

static void *dl_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct xt_hashroute_htable *htable = s->private;
	unsigned int *bucket = (unsigned int *)v;

	*pos = ++(*bucket);
	if (*pos >= htable->cfg.size) {
		kfree(v);
		return NULL;
	}
	return bucket;
}

static void dl_seq_stop(struct seq_file *s, void *v)
	__releases(htable->lock)
{
	struct xt_hashroute_htable *htable = s->private;
	unsigned int *bucket = (unsigned int *)v;

	if (!IS_ERR(bucket))
		kfree(bucket);
	spin_unlock_bh(&htable->lock);
}

static void dl_seq_print(struct dsthash_ent *ent, u_int8_t family,
			 struct seq_file *s)
{
	long exp;
	if(ent->dev == NULL) return;
	if(ent->expires == 0) {
		exp = -1;
	} else {
		exp = (long)(ent->expires - jiffies)/HZ;
	}
	switch (family) {
	case NFPROTO_IPV4:
		seq_printf(s, "%ld %pI4:%u->%pI4:%u %s\n",
			   exp,
			   &ent->dst.ip.src,
			   ntohs(ent->dst.src_port),
			   &ent->dst.ip.dst,
			   ntohs(ent->dst.dst_port),
			   ent->dev->name);
		break;
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	case NFPROTO_IPV6:
		seq_printf(s, "%ld %pI6:%u->%pI6:%u %s\n",
			   exp,
			   &ent->dst.ip6.src,
			   ntohs(ent->dst.src_port),
			   &ent->dst.ip6.dst,
			   ntohs(ent->dst.dst_port),
			   ent->dev->name);
		break;
#endif
	default:
		BUG();
	}
}

static int dl_seq_real_show(struct dsthash_ent *ent, u_int8_t family,
			    struct seq_file *s)
{
	spin_lock(&ent->lock);
	dl_seq_print(ent, family, s);
	spin_unlock(&ent->lock);
	
	return seq_has_overflowed(s);
}

static int dl_seq_show(struct seq_file *s, void *v)
{
	struct xt_hashroute_htable *htable = s->private;
	unsigned int *bucket = (unsigned int *)v;
	struct dsthash_ent *ent;

	if (!hlist_empty(&htable->hash[*bucket])) {
		hlist_for_each_entry(ent, &htable->hash[*bucket], node)
			if (dl_seq_real_show(ent, htable->family, s))
				return -1;
	}
	return 0;
}


static const struct seq_operations dl_seq_ops = {
	.start = dl_seq_start,
	.next  = dl_seq_next,
	.stop  = dl_seq_stop,
	.show  = dl_seq_show
};

static int dl_proc_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &dl_seq_ops);

	if (!ret) {
		struct seq_file *sf = file->private_data;

		sf->private = PDE_DATA(inode);
	}
	return ret;
}

static const struct file_operations dl_file_ops = {
	.owner   = THIS_MODULE,
	.open    = dl_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};

static int __net_init hashroute_proc_net_init(struct net *net)
{
	struct hashroute_net *hashroute_net = hashroute_pernet(net);

	hashroute_net->ipt_hashroute = proc_mkdir("ipt_hashroute", net->proc_net);
	if (!hashroute_net->ipt_hashroute)
		return -ENOMEM;
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	hashroute_net->ip6t_hashroute = proc_mkdir("ip6t_hashroute", net->proc_net);
	if (!hashroute_net->ip6t_hashroute) {
		remove_proc_entry("ipt_hashroute", net->proc_net);
		return -ENOMEM;
	}
#endif
	return 0;
}

static void __net_exit hashroute_proc_net_exit(struct net *net)
{
	struct xt_hashroute_htable *hinfo;
	struct hashroute_net *hashroute_net = hashroute_pernet(net);

	/* hashroute_net_exit() is called before hashroute_mt_destroy().
	 * Make sure that the parent ipt_hashroute and ip6t_hashroute proc
	 * entries is empty before trying to remove it.
	 */
	mutex_lock(&hashroute_mutex);
	hlist_for_each_entry(hinfo, &hashroute_net->htables, node)
		htable_remove_proc_entry(hinfo);
	hashroute_net->ipt_hashroute = NULL;
	hashroute_net->ip6t_hashroute = NULL;
	mutex_unlock(&hashroute_mutex);

	remove_proc_entry("ipt_hashroute", net->proc_net);
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	remove_proc_entry("ip6t_hashroute", net->proc_net);
#endif
}

static int __net_init hashroute_net_init(struct net *net)
{
	struct hashroute_net *hashroute_net = hashroute_pernet(net);

	INIT_HLIST_HEAD(&hashroute_net->htables);
	return hashroute_proc_net_init(net);
}

static void __net_exit hashroute_net_exit(struct net *net)
{
	hashroute_proc_net_exit(net);
}

static struct pernet_operations hashroute_net_ops = {
	.init	= hashroute_net_init,
	.exit	= hashroute_net_exit,
	.id	= &hashroute_net_id,
	.size	= sizeof(struct hashroute_net),
};

static int hashroute_tg_check_common(const struct xt_tgchk_param *par,
				     struct xt_hashroute_htable **hinfo,
				     struct hashroute_cfg *cfg,
				     const char *name)
{
	struct net *net = par->net;
	int ret = 0;

	if (cfg->gc_interval == 0)
		return -EINVAL;
	if (par->family == NFPROTO_IPV4) {
		if (cfg->srcmask > 32 || cfg->dstmask > 32)
			return -EINVAL;
	} else {
		if (cfg->srcmask > 128 || cfg->dstmask > 128)
			return -EINVAL;
	}

	/* Check for overflow. */
	mutex_lock(&hashroute_mutex);
	*hinfo = htable_find_get(net, name, par->family);
	if (*hinfo == NULL) {
		ret = htable_create(net, cfg, name, par->family,
				    hinfo, 0);
		if (ret >= 0) {
			ret = 0;
		}
	}
	
	mutex_unlock(&hashroute_mutex);

	return ret;
}

static int hashroute_tg_check(const struct xt_tgchk_param *par)
{
	struct xt_hashroute_mtinfo *info = par->targinfo;

	if (info->name[sizeof(info->name) - 1] != '\0')
		return -EINVAL;

	return hashroute_tg_check_common(par, &info->hinfo, &info->cfg,
					 info->name);
}

static unsigned int
hashroute_tg(struct sk_buff *skb,
				const struct xt_action_param *par)
{
	struct dsthash_ent *dh;
	struct dsthash_dst dst;
	struct xt_hashroute_mtinfo *info = par->targinfo;
	struct net_device * dev;
	int rc;

	if (hashroute_init_dst(info->hinfo, &dst, skb, par->thoff, 1, info->cfg.mode) < 0){
		pr_debug("hotdrop\n");
		return NF_DROP;
	}

	rcu_read_lock_bh();
	dh = dsthash_find(info->hinfo, &dst);
	if (dh == NULL) {
		pr_debug("not found 1: DROP %d\n", dst.ip.src);
		goto cont;
	}
	
	if(dh->dev == NULL){
		pr_debug("not found 2: DROP\n");
		goto cont_unlock;
	}
	
	dev = skb->dev;
	if(dev != dh->dev){
		pr_debug("setting network level header proto=%04x src=%08x dst=%08x", ntohs(skb->protocol), *(unsigned int*)dh->dev->dev_addr, *(unsigned int*)dh->header);
		if(!dev_hard_header(skb, dh->dev, ntohs(skb->protocol), dh->header, dh->dev->dev_addr, skb->len)){
			pr_debug("unable to insert hard header (Network Layer), might be fine for certain interfaces (i.e gre)\n");
		}
		
		if(dev){
			dev_put(dev);
		}
		dev = dh->dev;
		skb->dev = dev;
		dev_hold(dev);
	}
	
	spin_unlock(&dh->lock);
	rcu_read_unlock_bh();
	
	// this packet should be NOTRACK'ed
	skb->nfct = &nf_ct_untracked_get()->ct_general;
	nf_conntrack_get(skb->nfct);
	skb->nfctinfo = IP_CT_NEW;
	
	skb_dst_set(skb, NULL);
	skb->pkt_type = PACKET_OUTGOING;
	
	pr_debug("packet transmitting on device %s ref before=%d\n", skb->dev->name, netdev_refcnt_read(skb->dev));
	rc = dev_queue_xmit(skb);
	if (unlikely(rc != NET_XMIT_SUCCESS)) {
		printk_ratelimited(KERN_WARNING "dev_queue_xmit returned error: %d unable to re-route packet\n", rc);
	}
	
	dev_put(dev);
	pr_debug("done transmitting packet for device %s ref after=%d\n", dev->name, netdev_refcnt_read(dev));
	
    return NF_STOLEN;
	
cont_unlock:
	spin_unlock(&dh->lock);
cont:
	rcu_read_unlock_bh();
	return NF_ACCEPT;
}

static void hashroute_tg_destroy(const struct xt_tgdtor_param *par)
{
	const struct xt_hashroute_mtinfo *info = par->targinfo;

	htable_put(info->hinfo);
}

static struct xt_target hashroute_tg_reg[] __read_mostly = {
	{
		.name		= "HASHROUTE",
		.family		= NFPROTO_UNSPEC,
		.target		= hashroute_tg,
		.targetsize      = sizeof(struct xt_hashroute_mtinfo),
		.checkentry     = hashroute_tg_check,
		.destroy        = hashroute_tg_destroy,
		.me		= THIS_MODULE,
	}
};

static int __init hashroute_mt_init(void)
{
	int err;

	err = register_pernet_subsys(&hashroute_net_ops);
	if (err < 0)
		return err;
	err = xt_register_matches(hashroute_mt_reg,
	      ARRAY_SIZE(hashroute_mt_reg));
	if (err < 0)
		goto err1;
	
	
	err = xt_register_targets(hashroute_tg_reg,
	      ARRAY_SIZE(hashroute_tg_reg));
	if (err < 0)
		goto err1;

	err = -ENOMEM;
	hashroute_cachep = kmem_cache_create("xt_hashroute",
					    sizeof(struct dsthash_ent), 0, 0,
					    NULL);
	if (!hashroute_cachep) {
		pr_warn("unable to create slab cache\n");
		goto err2;
	}
	return 0;

err2:
	xt_unregister_matches(hashroute_mt_reg, ARRAY_SIZE(hashroute_mt_reg));
err1:
	unregister_pernet_subsys(&hashroute_net_ops);
	return err;

}


static void __exit hashroute_mt_exit(void)
{
	xt_unregister_matches(hashroute_mt_reg, ARRAY_SIZE(hashroute_mt_reg));
	xt_unregister_targets(hashroute_tg_reg, ARRAY_SIZE(hashroute_tg_reg));
	unregister_pernet_subsys(&hashroute_net_ops);

	rcu_barrier_bh();
	kmem_cache_destroy(hashroute_cachep);
}

module_init(hashroute_mt_init);
module_exit(hashroute_mt_exit);

/* TODO xt_ROUTE like target for routing */