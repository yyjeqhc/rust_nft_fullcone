#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/workqueue.h>
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
#include <linux/notifier.h>
#endif
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_ecache.h>

// nf_ct_get
// nf_ct_net
// nf_ct_zone
// xt_hooknum
// dev_put
// HOOK2MANIP
// xt_out
// xt_in
// be16_to_cpu

// nf_ct_get
struct nf_conn *rust_helper_nf_ct_get(struct sk_buff *skb, enum ip_conntrack_info *ctinfo) {
    return nf_ct_get(skb, ctinfo);
}

// nf_ct_net
struct net *rust_helper_nf_ct_net(struct nf_conn *ct) {
    return nf_ct_net(ct);
}

// nf_ct_zone
const struct nf_conntrack_zone *rust_helper_nf_ct_zone(struct nf_conn *ct) {
    return nf_ct_zone(ct);
}

// xt_hooknum
unsigned int rust_helper_xt_hooknum(const struct xt_action_param *par) {
    return xt_hooknum(par);
}

// dev_put
void rust_helper_dev_put(struct net_device *dev) {
    dev_put(dev);
}


// HOOK2MANIP (宏转为函数)
unsigned int rust_helper_HOOK2MANIP(unsigned int hooknum) {
    return HOOK2MANIP(hooknum);
}

// xt_out
struct net_device *rust_helper_xt_out(const struct xt_action_param *par) {
    return xt_out(par);
}

// xt_in
struct net_device *rust_helper_xt_in(const struct xt_action_param *par) {
    return xt_in(par);
}

// be16_to_cpu
uint16_t rust_helper_be16_to_cpu(uint16_t val) {
    return be16_to_cpu(val);
}



#include <linux/version.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/jhash.h>

#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
#include <linux/notifier.h>
#endif

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#if IS_ENABLED(CONFIG_NF_NAT_IPV6) || (IS_ENABLED(CONFIG_IPV6) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0))
#include <linux/netfilter_ipv6.h>
#include <linux/ipv6.h>
#include <net/addrconf.h>
#endif

#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/inetdevice.h>
#include <linux/netfilter/nf_tables.h>

#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_ecache.h>




#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_nat.h>

#include <linux/workqueue.h>


unsigned int rust_helper_nft_hook(const struct nft_pktinfo *pkt)
{
    return nft_hook(pkt);
}

const struct net_device *rust_helper_nft_out(const struct nft_pktinfo *pkt)
{
    return nft_out(pkt);
}

u16 rust_helper_nft_reg_load16(const u32 *reg)
{
    return nft_reg_load16(reg);
}

void *rust_helper_nft_expr_priv(const struct nft_expr *expr)
{
    return nft_expr_priv(expr);
}

struct rtable *rust_helper_skb_rtable(const struct sk_buff *skb)
{
    return skb_rtable(skb);
}

__be32 rust_helper_rt_nexthop(const struct rtable *rt, __be32 daddr)
{
    return rt_nexthop(rt, daddr);
}
