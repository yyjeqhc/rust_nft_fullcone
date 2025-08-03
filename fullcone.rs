// SPDX-License-Identifier: GPL-2.0-only
//! Rust implementation of nftables fullcone expression support.

use kernel::prelude::*;
use kernel::alloc::{flags, KBox};
use kernel::bindings;

module! {
    type: NftFullconeModule,
    name: "nft_fullcone",
    author: "yyjeqhc <1772413353@qq.com>",
    description: "Netfilter nftables fullcone expression support in Rust",
    license: "GPL",
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
struct NatMapping {
    int_addr: u32,      // 内部地址 (big-endian)
    int_port: u16,      // 内部端口 (big-endian)
    map_ip: u32,        // 映射地址 (big-endian)
    map_port: u16,      // 映射端口 (big-endian)
    ext_addr: u32,      // 外部地址 (big-endian)
    ext_port: u16,      // 外部端口 (big-endian)
}

struct LockedKVec {
    lock: bindings::spinlock_t,
    data: KVec<NatMapping>,
}

static mut MAPPINGS: *mut LockedKVec = core::ptr::null_mut();

struct NftFullconeModule {
    expr_type_ptr: u64,
    expr_ops_ptr: u64,
    policy_ptr: u64,
}

impl kernel::Module for NftFullconeModule {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("nft_fullcone: module being initialized\n");
        
        static mut MAPPINGS_KEY: bindings::lock_class_key = unsafe { core::mem::zeroed() };
        
        let locked_kvec = KBox::new(LockedKVec {
            lock: unsafe { core::mem::zeroed() }, 
            data: KVec::new(),
        }, flags::GFP_KERNEL)?;

        unsafe {
            MAPPINGS = KBox::into_raw(locked_kvec);
            let name = b"nft_fullcone_lock\0".as_ptr();
            
            bindings::__spin_lock_init(
                &mut (*MAPPINGS).lock,
                name,
                &raw mut MAPPINGS_KEY,
            );
        }

        let policy = KBox::new([bindings::nla_policy::default(); 4], flags::GFP_KERNEL)?;
        let mut expr_ops = KBox::new(nft_fullcone_ipv4_ops(), flags::GFP_KERNEL)?;
        let mut expr_type = KBox::new(bindings::nft_expr_type::default(), flags::GFP_KERNEL)?;

        let policy_ptr_raw = KBox::into_raw(policy);
        
        expr_type.ops = &*expr_ops;
        expr_type.policy = policy_ptr_raw as *const _; 
        expr_type.name = b"fullcone\0".as_ptr();
        expr_type.family = bindings::NFPROTO_IPV4 as u8;
        expr_type.maxattr = 3;

        expr_type.owner = &raw mut bindings::__this_module as *mut _ ;
        
        expr_ops.type_ = &*expr_type;
        
        let expr_type_ptr_raw = KBox::into_raw(expr_type);
        let expr_ops_ptr_raw = KBox::into_raw(expr_ops);

        let ret = unsafe { bindings::nft_register_expr(expr_type_ptr_raw) };
        if ret != 0 {
            pr_err!("nft_fullcone: failed to register expression: {}\n", ret);
            unsafe {
                if !MAPPINGS.is_null() {
                    let _ = KBox::from_raw(MAPPINGS);
                    MAPPINGS = core::ptr::null_mut();
                }
                let _ = KBox::from_raw(expr_type_ptr_raw);
                let _ = KBox::from_raw(expr_ops_ptr_raw);
                let _ = KBox::from_raw(policy_ptr_raw);
            }
            return Err(kernel::error::Error::from_errno(ret));
        }

        pr_info!("nft_fullcone: module initialized successfully\n");
        
        Ok(NftFullconeModule {
            expr_type_ptr: expr_type_ptr_raw as u64,
            expr_ops_ptr: expr_ops_ptr_raw as u64,
            policy_ptr: policy_ptr_raw as u64,
        })
    }
}

impl Drop for NftFullconeModule {
    fn drop(&mut self) {
        pr_info!("nft_fullcone: module being removed\n");
        unsafe {
            bindings::nft_unregister_expr(self.expr_type_ptr as *mut bindings::nft_expr_type);
            
            let _ = KBox::from_raw(self.expr_type_ptr as *mut bindings::nft_expr_type);
            let _ = KBox::from_raw(self.expr_ops_ptr as *mut bindings::nft_expr_ops);
            let _ = KBox::from_raw(self.policy_ptr as *mut [bindings::nla_policy; 4]);

            if !MAPPINGS.is_null() {
                let _ = KBox::from_raw(MAPPINGS);
                MAPPINGS = core::ptr::null_mut();
            }
        }
        pr_info!("nft_fullcone: module removed\n");
    }
}

fn get_device_ip(device: &bindings::net_device) -> u32 {
    unsafe {
        bindings::__rcu_read_lock();
        let in_dev = (*device).ip_ptr;
        if in_dev.is_null() { bindings::__rcu_read_unlock(); return 0; }
        let ifa_list = (*in_dev).ifa_list;
        if ifa_list.is_null() { bindings::__rcu_read_unlock(); return 0; }
        let ip = (*ifa_list).ifa_local;
        bindings::__rcu_read_unlock();
        ip
    }
}

fn get_proper_port(src_port: u16) -> u16 {
    if src_port == 0 { 1024u16.to_be() } else { src_port }
}

#[allow(non_upper_case_globals)]
extern "C" fn nft_fullcone_ipv4_eval(_expr: *const bindings::nft_expr, regs: *mut bindings::nft_regs, pkt: *const bindings::nft_pktinfo) {
    unsafe {
        if MAPPINGS.is_null() { return; }
        let mappings_lock = &mut *MAPPINGS;
        
        let raw_lock = &mut (*mappings_lock).lock as *mut bindings::spinlock_t as *mut bindings::raw_spinlock_t;
        
        let mut range = bindings::nf_nat_range2::default();
        let hooknum = bindings::nft_hook(pkt);
        let skb: *mut bindings::sk_buff = (*pkt).skb;

        let mut ctinfo: u32 = 0;
        let ct = bindings::nf_ct_get(skb, &mut ctinfo);
        if ct.is_null() { return; }

        let ct_tuple_origin = &(*ct).tuplehash[bindings::ip_conntrack_dir_IP_CT_DIR_ORIGINAL as usize].tuple;
        if ct_tuple_origin.dst.protonum as u32 != bindings::IPPROTO_UDP { return; }

        match hooknum {
            bindings::nf_inet_hooks_NF_INET_PRE_ROUTING => {
                let dst_ip = ct_tuple_origin.dst.u3.ip;
                let dst_port = ct_tuple_origin.dst.u.udp.port;
                
                bindings::_raw_spin_lock(raw_lock);
                let found = mappings_lock.data.iter().find(|m| m.map_ip == dst_ip && m.map_port == dst_port).copied();
                bindings::_raw_spin_unlock(raw_lock);
                
                if let Some(mapping) = found {
                    range.flags = bindings::NF_NAT_RANGE_MAP_IPS | bindings::NF_NAT_RANGE_PROTO_SPECIFIED;
                    range.min_addr.ip = mapping.int_addr;
                    range.max_addr.ip = mapping.int_addr;
                    range.min_proto.udp.port = mapping.int_port;
                    range.max_proto = range.min_proto;
                    (*regs).__bindgen_anon_1.verdict.code = bindings::nf_nat_setup_info(ct, &range, bindings::HOOK2MANIP(hooknum) as i32);
                }
            }
            bindings::nf_inet_hooks_NF_INET_POST_ROUTING => {
                let src_ip = ct_tuple_origin.src.u3.ip;
                let src_port = ct_tuple_origin.src.u.udp.port;
                let dst_ip = ct_tuple_origin.dst.u3.ip;
                let dst_port = ct_tuple_origin.dst.u.udp.port;

                let out: *const bindings::net_device = bindings::nft_out(pkt);
                let map_ip = if !out.is_null() { get_device_ip(&*out) } else { 0 };
                let map_port = get_proper_port(src_port);
                
                if map_ip == 0 { return; }

                range.flags = bindings::NF_NAT_RANGE_MAP_IPS | bindings::NF_NAT_RANGE_PROTO_SPECIFIED;
                range.min_addr.ip = map_ip;
                range.max_addr.ip = map_ip;
                range.min_proto.udp.port = map_port;
                range.max_proto = range.min_proto;

                bindings::_raw_spin_lock(raw_lock);
                if !mappings_lock.data.iter().any(|m| m.int_addr == src_ip && m.int_port == src_port) {
                    let new_mapping = NatMapping { int_addr: src_ip, int_port: src_port, map_ip, map_port, ext_addr: dst_ip, ext_port: dst_port };
                    if mappings_lock.data.push(new_mapping, flags::GFP_ATOMIC).is_err() {
                        pr_warn!("Failed to add mapping (OOM)\n");
                    }
                }
                bindings::_raw_spin_unlock(raw_lock);
                
                (*regs).__bindgen_anon_1.verdict.code = bindings::nf_nat_setup_info(ct, &range, bindings::HOOK2MANIP(hooknum) as i32);
            }
            _ => {}
        }
    }
}

extern "C" fn nft_fullcone_init(_ctx: *const bindings::nft_ctx, _expr: *const bindings::nft_expr, _tb: *const *const bindings::nlattr) -> i32 { 0 }
extern "C" fn nft_fullcone_destroy(_ctx: *const bindings::nft_ctx, _expr: *const bindings::nft_expr) {}
extern "C" fn nft_fullcone_dump(_skb: *mut bindings::sk_buff, _expr: *const bindings::nft_expr, _reset: bool) -> i32 { 0 }
extern "C" fn nft_fullcone_validate(ctx: *const bindings::nft_ctx, _expr: * const bindings::nft_expr) -> i32 {
    let err = unsafe { bindings::nft_chain_validate_dependency((*ctx).chain, bindings::nft_chain_types_NFT_CHAIN_T_NAT) };
    if err < 0 { return err; }
    let err = unsafe {
        bindings::nft_chain_validate_hooks((*ctx).chain, (1 << bindings::nf_inet_hooks_NF_INET_PRE_ROUTING) | (1 << bindings::nf_inet_hooks_NF_INET_POST_ROUTING))
    };
    err
}

#[repr(C)]
struct NftFullconePriv { _flags: u32, _sreg_proto_min: u8, _sreg_proto_max: u8 }

fn nft_fullcone_ipv4_ops() -> bindings::nft_expr_ops {
    bindings::nft_expr_ops {
        size: core::mem::size_of::<NftFullconePriv>() as u32,
        eval: Some(nft_fullcone_ipv4_eval),
        init: Some(nft_fullcone_init),
        destroy: Some(nft_fullcone_destroy),
        dump: Some(nft_fullcone_dump),
        validate: Some(nft_fullcone_validate),
        ..bindings::nft_expr_ops::default()
    }
}