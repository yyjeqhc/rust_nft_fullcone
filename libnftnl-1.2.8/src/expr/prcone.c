/*
 * (C) 2022 wongsyrone
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>

#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nftnl_expr_prcone {
	uint32_t		flags;
	enum nft_registers	sreg_proto_min;
	enum nft_registers	sreg_proto_max;
};

static int
nftnl_expr_prcone_set(struct nftnl_expr *e, uint16_t type,
		       const void *data, uint32_t data_len)
{
	struct nftnl_expr_prcone *prcone = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_PRCONE_FLAGS:
		memcpy(&prcone->flags, data, sizeof(prcone->flags));
		break;
	case NFTNL_EXPR_PRCONE_REG_PROTO_MIN:
		memcpy(&prcone->sreg_proto_min, data, sizeof(prcone->sreg_proto_min));
		break;
	case NFTNL_EXPR_PRCONE_REG_PROTO_MAX:
		memcpy(&prcone->sreg_proto_max, data, sizeof(prcone->sreg_proto_max));
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_prcone_get(const struct nftnl_expr *e, uint16_t type,
		       uint32_t *data_len)
{
	struct nftnl_expr_prcone *prcone = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_PRCONE_FLAGS:
		*data_len = sizeof(prcone->flags);
		return &prcone->flags;
	case NFTNL_EXPR_PRCONE_REG_PROTO_MIN:
		*data_len = sizeof(prcone->sreg_proto_min);
		return &prcone->sreg_proto_min;
	case NFTNL_EXPR_PRCONE_REG_PROTO_MAX:
		*data_len = sizeof(prcone->sreg_proto_max);
		return &prcone->sreg_proto_max;
	}
	return NULL;
}

static int nftnl_expr_prcone_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_PRCONE_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case NFTA_PRCONE_REG_PROTO_MIN:
	case NFTA_PRCONE_REG_PROTO_MAX:
	case NFTA_PRCONE_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_prcone_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_prcone *prcone = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_PRCONE_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_PRCONE_FLAGS, htobe32(prcone->flags));
	if (e->flags & (1 << NFTNL_EXPR_PRCONE_REG_PROTO_MIN))
		mnl_attr_put_u32(nlh, NFTA_PRCONE_REG_PROTO_MIN,
				 htobe32(prcone->sreg_proto_min));
	if (e->flags & (1 << NFTNL_EXPR_PRCONE_REG_PROTO_MAX))
		mnl_attr_put_u32(nlh, NFTA_PRCONE_REG_PROTO_MAX,
				 htobe32(prcone->sreg_proto_max));
}

static int
nftnl_expr_prcone_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_prcone *prcone = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_PRCONE_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_expr_prcone_cb, tb) < 0)
		return -1;

	if (tb[NFTA_PRCONE_FLAGS]) {
		prcone->flags = be32toh(mnl_attr_get_u32(tb[NFTA_PRCONE_FLAGS]));
		e->flags |= (1 << NFTNL_EXPR_PRCONE_FLAGS);
        }
	if (tb[NFTA_PRCONE_REG_PROTO_MIN]) {
		prcone->sreg_proto_min =
			be32toh(mnl_attr_get_u32(tb[NFTA_PRCONE_REG_PROTO_MIN]));
		e->flags |= (1 << NFTNL_EXPR_PRCONE_REG_PROTO_MIN);
	}
	if (tb[NFTA_PRCONE_REG_PROTO_MAX]) {
		prcone->sreg_proto_max =
			be32toh(mnl_attr_get_u32(tb[NFTA_PRCONE_REG_PROTO_MAX]));
		e->flags |= (1 << NFTNL_EXPR_PRCONE_REG_PROTO_MAX);
	}

	return 0;
}

static int nftnl_expr_prcone_snprintf(char *buf, size_t remain,
				    uint32_t flags, const struct nftnl_expr *e)
{
	struct nftnl_expr_prcone *prcone = nftnl_expr_data(e);
	int offset = 0, ret = 0;

	if (e->flags & (1 << NFTNL_EXPR_PRCONE_REG_PROTO_MIN)) {
		ret = snprintf(buf + offset, remain, "proto_min reg %u ",
			       prcone->sreg_proto_min);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}
	if (e->flags & (1 << NFTNL_EXPR_PRCONE_REG_PROTO_MAX)) {
		ret = snprintf(buf + offset, remain, "proto_max reg %u ",
			       prcone->sreg_proto_max);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}
	if (e->flags & (1 << NFTNL_EXPR_PRCONE_FLAGS)) {
		ret = snprintf(buf + offset, remain, "flags 0x%x ", prcone->flags);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	return offset;
}

struct expr_ops expr_ops_prcone = {
	.name		= "prcone",
	.alloc_len	= sizeof(struct nftnl_expr_prcone),
	.nftnl_max_attr	= __NFTNL_EXPR_PRCONE_MAX - 1,
	.set		= nftnl_expr_prcone_set,
	.get		= nftnl_expr_prcone_get,
	.parse		= nftnl_expr_prcone_parse,
	.build		= nftnl_expr_prcone_build,
	.output	= nftnl_expr_prcone_snprintf,
};

