/* ip6tables match extension for limiting packets per destination
 *
 * (C) 2003-2004 by Harald Welte <laforge@netfilter.org>
 *
 * Development of this code was funded by Astaro AG, http://www.astaro.com/
 *
 * Based on ipt_limit.c by
 * Jérôme de Vivie   <devivie@info.enserb.u-bordeaux.fr>
 * Hervé Eychenne    <rv@wallfire.org>
 * 
 * Error corections by nmalykh@bilim.com (22.01.2005)
 */
#define _BSD_SOURCE 1
#define _ISOC99_SOURCE 1
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <xtables.h>
#include "xt_hashroute.h"

/* miliseconds */
#define XT_HASHROUTE_GCINTERVAL	1000

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

struct hashroute_mt_udata {
	uint32_t mult;
};

enum {
	O_UPTO = 0,
	O_ABOVE,
	O_LIMIT,
	O_MODE,
	O_SRCMASK,
	O_DSTMASK,
	O_NAME,
	O_HTABLE_SIZE,
	O_HTABLE_MAX,
	O_HTABLE_GCINT,
	O_HTABLE_EXPIRE,
	F_HTABLE_EXPIRE = 1 << O_HTABLE_EXPIRE,
};

static void hashroute_mt_help(void)
{
	printf(
"HASHROUTE target options:\n"
"  --hashroute-mode <mode>          mode is a comma-separated list of\n"
"                                   dstip,srcip,dstport,srcport (or none)\n"
"  --hashroute-srcmask <length>     source address grouping prefix length\n"
"  --hashroute-dstmask <length>     destination address grouping prefix length\n"
"  --hashroute-name <name>          name for /proc/net/ipt_hashroute\n"
"  --hashroute-htable-size <num>    number of hashtable buckets\n"
"  --hashroute-htable-max <num>     number of hashtable entries\n"
"  --hashroute-htable-gcinterval    interval between garbage collection runs\n"
"  --hashroute-htable-expire        after which time are idle entries expired?\n"
"\n");
}

#define s struct xt_hashroute_mtinfo
static const struct xt_option_entry hashroute_mt_opts[] = {
	{.name = "hashroute-srcmask", .id = O_SRCMASK, .type = XTTYPE_PLEN},
	{.name = "hashroute-dstmask", .id = O_DSTMASK, .type = XTTYPE_PLEN},
	{.name = "hashroute-htable-size", .id = O_HTABLE_SIZE,
	 .type = XTTYPE_UINT32, .flags = XTOPT_PUT,
	 XTOPT_POINTER(s, cfg.size)},
	{.name = "hashroute-htable-max", .id = O_HTABLE_MAX,
	 .type = XTTYPE_UINT32, .flags = XTOPT_PUT,
	 XTOPT_POINTER(s, cfg.max)},
	{.name = "hashroute-htable-gcinterval", .id = O_HTABLE_GCINT,
	 .type = XTTYPE_UINT32, .flags = XTOPT_PUT,
	 XTOPT_POINTER(s, cfg.gc_interval)},
	{.name = "hashroute-htable-expire", .id = O_HTABLE_EXPIRE,
	 .type = XTTYPE_UINT32, .flags = XTOPT_PUT,
	 XTOPT_POINTER(s, cfg.expire)},
	{.name = "hashroute-mode", .id = O_MODE, .type = XTTYPE_STRING},
	{.name = "hashroute-name", .id = O_NAME, .type = XTTYPE_STRING,
	 .flags = XTOPT_MAND | XTOPT_PUT, XTOPT_POINTER(s, name), .min = 1},
	XTOPT_TABLEEND,
};
#undef s

static void hashroute_mt4_init(struct xt_entry_target *match)
{
	struct xt_hashroute_mtinfo *info = (void *)match->data;

	info->cfg.mode        = 0;
	info->cfg.gc_interval = XT_HASHROUTE_GCINTERVAL;
	info->cfg.srcmask     = 32;
	info->cfg.dstmask     = 32;
}

static void hashroute_mt6_init(struct xt_entry_target *match)
{
	struct xt_hashroute_mtinfo *info = (void *)match->data;

	info->cfg.mode        = 0;
	info->cfg.gc_interval = XT_HASHROUTE_GCINTERVAL;
	info->cfg.srcmask     = 128;
	info->cfg.dstmask     = 128;
}

/* Parse a 'mode' parameter into the required bitmask */
static int parse_mode(uint32_t *mode, const char *option_arg)
{
	char *tok;
	char *arg = strdup(option_arg);

	if (!arg)
		return -1;

	for (tok = strtok(arg, ",|");
	     tok;
	     tok = strtok(NULL, ",|")) {
		if (!strcmp(tok, "dstip"))
			*mode |= XT_HASHROUTE_HASH_DIP;
		else if (!strcmp(tok, "srcip"))
			*mode |= XT_HASHROUTE_HASH_SIP;
		else if (!strcmp(tok, "srcport"))
			*mode |= XT_HASHROUTE_HASH_SPT;
		else if (!strcmp(tok, "dstport"))
			*mode |= XT_HASHROUTE_HASH_DPT;
		else {
			free(arg);
			return -1;
		}
	}
	free(arg);
	return 0;
}

static void hashroute_mt_parse(struct xt_option_call *cb)
{
	struct xt_hashroute_mtinfo *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_MODE:
		if (parse_mode(&info->cfg.mode, cb->arg) < 0)
			xtables_param_act(XTF_BAD_VALUE, "hashroute",
			          "--hashroute-mode", cb->arg);
		break;
	case O_SRCMASK:
		info->cfg.srcmask = cb->val.hlen;
		break;
	case O_DSTMASK:
		info->cfg.dstmask = cb->val.hlen;
		break;
	}
}

static void hashroute_mt_check(struct xt_fcheck_call *cb)
{
	const struct hashroute_mt_udata *udata = cb->udata;
	struct xt_hashroute_mtinfo *info = cb->data;

	if (!(cb->xflags & F_HTABLE_EXPIRE))
		info->cfg.expire = udata->mult * 1000; /* from s to msec */
}

static void print_mode(unsigned int mode, char separator)
{
	bool prevmode = false;

	putchar(' ');
	if (mode & XT_HASHROUTE_HASH_SIP) {
		fputs("srcip", stdout);
		prevmode = 1;
	}
	if (mode & XT_HASHROUTE_HASH_SPT) {
		if (prevmode)
			putchar(separator);
		fputs("srcport", stdout);
		prevmode = 1;
	}
	if (mode & XT_HASHROUTE_HASH_DIP) {
		if (prevmode)
			putchar(separator);
		fputs("dstip", stdout);
		prevmode = 1;
	}
	if (mode & XT_HASHROUTE_HASH_DPT) {
		if (prevmode)
			putchar(separator);
		fputs("dstport", stdout);
	}
}

static void
hashroute_mt_print(const struct hashroute_cfg *cfg, unsigned int dmask, int revision)
{
	fputs(" route: ", stdout);

	if (cfg->mode & (XT_HASHROUTE_HASH_SIP | XT_HASHROUTE_HASH_SPT |
	    XT_HASHROUTE_HASH_DIP | XT_HASHROUTE_HASH_DPT)) {
		fputs(" mode", stdout);
		print_mode(cfg->mode, '-');
	}
	if (cfg->size != 0)
		printf(" htable-size %u", cfg->size);
	if (cfg->max != 0)
		printf(" htable-max %u", cfg->max);
	if (cfg->gc_interval != XT_HASHROUTE_GCINTERVAL)
		printf(" htable-gcinterval %u", cfg->gc_interval);
	printf(" htable-expire %u", cfg->expire);

	if (cfg->srcmask != dmask)
		printf(" srcmask %u", cfg->srcmask);
	if (cfg->dstmask != dmask)
		printf(" dstmask %u", cfg->dstmask);
}

static void
hashroute_mt4_print(const void *ip, const struct xt_entry_target *match,
                   int numeric)
{
	const struct xt_hashroute_mtinfo *info = (const void *)match->data;

	hashroute_mt_print(&info->cfg, 32, 2);
}

static void
hashroute_mt6_print(const void *ip, const struct xt_entry_target *match,
                   int numeric)
{
	const struct xt_hashroute_mtinfo *info = (const void *)match->data;

	hashroute_mt_print(&info->cfg, 128, 2);
}

static void
hashroute_mt_save(const struct hashroute_cfg *cfg, const char* name, unsigned int dmask, int revision)
{
	fputs(" --hashroute", stdout);

	if (cfg->mode & (XT_HASHROUTE_HASH_SIP | XT_HASHROUTE_HASH_SPT |
	    XT_HASHROUTE_HASH_DIP | XT_HASHROUTE_HASH_DPT)) {
		fputs(" --hashroute-mode", stdout);
		print_mode(cfg->mode, ',');
	}

	printf(" --hashroute-name %s", name);

	if (cfg->size != 0)
		printf(" --hashroute-htable-size %u", cfg->size);
	if (cfg->max != 0)
		printf(" --hashroute-htable-max %u", cfg->max);
	if (cfg->gc_interval != XT_HASHROUTE_GCINTERVAL)
		printf(" --hashroute-htable-gcinterval %u", cfg->gc_interval);

	printf(" --hashroute-htable-expire %u", cfg->expire);

	if (cfg->srcmask != dmask)
		printf(" --hashroute-srcmask %u", cfg->srcmask);
	if (cfg->dstmask != dmask)
		printf(" --hashroute-dstmask %u", cfg->dstmask);
}

static void
hashroute_mt4_save(const void *ip, const struct xt_entry_target *match)
{
	const struct xt_hashroute_mtinfo *info = (const void *)match->data;

	hashroute_mt_save(&info->cfg, info->name, 32, 2);
}

static void
hashroute_mt6_save(const void *ip, const struct xt_entry_target *match)
{
	const struct xt_hashroute_mtinfo *info = (const void *)match->data;

	hashroute_mt_save(&info->cfg, info->name, 128, 2);
}

static struct xtables_target hashroute_tg_reg[] = {
	{
		.version       = XTABLES_VERSION,
		.name          = "HASHROUTE",
		.revision      = 0,
		.family        = NFPROTO_IPV4,
		.size          = XT_ALIGN(sizeof(struct xt_hashroute_mtinfo)),
		.userspacesize = offsetof(struct xt_hashroute_mtinfo, hinfo),
		.help          = hashroute_mt_help,
		.init          = hashroute_mt4_init,
		.x6_parse      = hashroute_mt_parse,
		.x6_fcheck     = hashroute_mt_check,
		.print         = hashroute_mt4_print,
		.save          = hashroute_mt4_save,
		.x6_options    = hashroute_mt_opts,
		.udata_size    = sizeof(struct hashroute_mt_udata),
	},
	{
		.version       = XTABLES_VERSION,
		.name          = "HASHROUTE",
		.revision      = 0,
		.family        = NFPROTO_IPV6,
		.size          = XT_ALIGN(sizeof(struct xt_hashroute_mtinfo)),
		.userspacesize = offsetof(struct xt_hashroute_mtinfo, hinfo),
		.help          = hashroute_mt_help,
		.init          = hashroute_mt6_init,
		.x6_parse      = hashroute_mt_parse,
		.x6_fcheck     = hashroute_mt_check,
		.print         = hashroute_mt6_print,
		.save          = hashroute_mt6_save,
		.x6_options    = hashroute_mt_opts,
		.udata_size    = sizeof(struct hashroute_mt_udata),
	},
};

void _init(void)
{
	xtables_register_targets(hashroute_tg_reg, ARRAY_SIZE(hashroute_tg_reg));
}
