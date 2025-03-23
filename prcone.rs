// SPDX-License-Identifier: GPL-2.0-only
//! Rust implementation of nftables prcone expression support.

use core::ffi;
use kernel::prelude::*;
use kernel::alloc::flags;
use kernel::bindings::{self, *};
use core::net::Ipv4Addr;

module! {
    type: NftPrconeModule,
    name: "nft_prcone",
    author: "Syrone Wong <wong.syrone@gmail.com>",
    description: "Netfilter nftables prcone expression support in Rust",
    license: "GPL",
}

// 定义 NAT 映射结构体，与 xt_prcone 示例一致
#[derive(Debug)]
struct NatMapping {
    int_addr: u32,      // 内部地址 (big-endian)
    int_port: u16,      // 内部端口 (big-endian)
    map_ip: u32,        // 映射地址 (big-endian)
    map_port: u16,      // 映射端口 (big-endian)
    ext_addr: u32,      // 外部地址 (big-endian)
    ext_port: u16,      // 外部端口 (big-endian)
}

// 全局静态映射表
static mut MAPPINGS: KVec<NatMapping> = KVec::new();

// 模块主结构体，只存储指针
struct NftPrconeModule {
    expr_ops_ipv4: u64,   // nft_expr_ops 指针
    expr_type_ipv4: u64,  // nft_expr_type 指针
}


impl kernel::Module for NftPrconeModule {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("nft_prcone: module being initialized\n");

        // 创建 nft_expr_ops
        let mut expr_ops = KBox::new(nft_prcone_ipv4_ops(), flags::GFP_KERNEL)?;
        let expr_ops_ptr = KBox::into_raw(expr_ops) as u64;

        // 创建并设置 nft_expr_type
        let mut expr_type = KBox::new(nft_expr_type::default(), flags::GFP_KERNEL)?;
        expr_type.name = "prcone\0".as_ptr() as *const u8;
        expr_type.family = NFPROTO_IPV4 as u8;
        expr_type.ops = expr_ops_ptr as *const nft_expr_ops;
        expr_type.policy = nft_prcone_policy().as_ptr() as *const _;
        // expr_type.maxattr = NftPrconeAttributes::NFTA_PRCONE_MAX as u32;
        expr_type.maxattr = 3;

        expr_type.owner = unsafe { &mut __this_module as *mut _ };

        

        let expr_type_ptr = KBox::into_raw(expr_type);

        unsafe {
            let mut t = KBox::from_raw(expr_ops_ptr as *mut nft_expr_ops);
            t.type_ = expr_type_ptr as *const _;
            KBox::into_raw(t);
        }

        let ret = unsafe { bindings::nft_register_expr(expr_type_ptr) };
        // if ret != 0 {
        //     unsafe {
        //         KBox::from_raw(expr_ops_ptr as *mut nft_expr_ops);
        //         KBox::from_raw(expr_type_ptr);
        //     }
        //     return Err(kernel::error::Error::from_errno(ret));
        // }

        pr_info!("nft_prcone: module initialized successfully\n");
        Ok(NftPrconeModule {
            expr_ops_ipv4: expr_ops_ptr,
            expr_type_ipv4: expr_type_ptr as u64,
        })
    }
}

impl Drop for NftPrconeModule {
    fn drop(&mut self) {
        pr_info!("nft_prcone: module being removed\n");

        unsafe {
            bindings::nft_unregister_expr(self.expr_type_ipv4 as *mut nft_expr_type);
            let expr_os = KBox::from_raw(self.expr_ops_ipv4 as *mut nft_expr_ops);  // 释放 ops
            let expr_type = KBox::from_raw(self.expr_type_ipv4 as *mut nft_expr_type); // 释放 type
        }

        pr_info!("nft_prcone: mappings cleared\n");
    }
}

// // NAT 表达式私有数据
// #[repr(C)]
// struct NftPrcone {
//     flags: u32,
//     sreg_proto_min: u8,
//     sreg_proto_max: u8,
// }

// 获取设备 IP 地址
fn get_device_ip(device: &net_device) -> u32 {
    unsafe {
        bindings::__rcu_read_lock();
        let in_dev = device.ip_ptr;
        if in_dev.is_null() {
            bindings::__rcu_read_unlock();
            return 0;
        }
        let if_info = (*in_dev).ifa_list;
        if if_info.is_null() {
            bindings::__rcu_read_unlock();
            return 0;
        }
        let ip = (*if_info).ifa_local;
        bindings::__rcu_read_unlock();
        // pr_info!("device ip: {}\n", Ipv4Addr::from_bits(ip.to_be()));
        ip // 返回 big-endian IP
    }
}

// 简单端口选择逻辑
fn get_proper_port(src_port: u16) -> u16 {
    if src_port == 0 {
        1024_u16.to_be() // 默认使用 1024
    } else {
        src_port.to_be()
    }
}

// 设置 NAT 范围
fn nft_prcone_set_regs(expr: *const nft_expr, regs: *const nft_regs, range: &mut nf_nat_range2) {
    // unsafe {
    //     let priv = bindings::nft_expr_priv(expr) as *const NftPrcone;
    //     range.flags = (*priv).flags;
    //     if (*priv).sreg_proto_min != 0 {
    //         range.min_proto.all = bindings::nft_reg_load16(&(*regs).data[(*priv).sreg_proto_min as usize]) as u16;
    //         range.max_proto.all = bindings::nft_reg_load16(&(*regs).data[(*priv).sreg_proto_max as usize]) as u16;
    //     }
    // }

}

// IPv4 prcone 评估函数
extern "C" fn nft_prcone_ipv4_eval(expr: *const nft_expr, regs: *mut nft_regs, pkt: *const nft_pktinfo) {
    let mut range = nf_nat_range2::default();
    unsafe {
        // nft_prcone_set_regs(expr, regs, &mut range);

        let hooknum = bindings::nft_hook(pkt);
        let skb: *mut sk_buff = (*pkt).skb;
        let out: *const net_device = bindings::nft_out(pkt);


        let mut ctinfo: u32 = 0;
        let ct = bindings::nf_ct_get(skb, &mut ctinfo);
        if ct.is_null() {
            // (*regs).__bindgen_anon_1.verdict.code = NFT_CONTINUE;
            // pr_err!("is_null \n");
            return;
        }

        let ct_tuple_origin = (*ct).tuplehash[ip_conntrack_dir_IP_CT_DIR_ORIGINAL as usize].tuple;
        let protonum = ct_tuple_origin.dst.protonum as u32;
        if protonum != IPPROTO_UDP {
            // pr_err!("protonum {}\n",protonum);

            return;
        }

        match hooknum {
            nf_inet_hooks_NF_INET_PRE_ROUTING => {
                let src_ip = ct_tuple_origin.src.u3.ip.to_be();
                let src_port = ct_tuple_origin.src.u.udp.port.to_be();
                let dst_ip = ct_tuple_origin.dst.u3.ip.to_be();
                let dst_port = ct_tuple_origin.dst.u.udp.port.to_be();
                
                // pr_err!("nft_prcone: INBOUND DNAT from {}:{} to {}:{}\n",
                //             Ipv4Addr::from_bits(src_ip), src_port,
                //             Ipv4Addr::from_bits(dst_ip), dst_port);

                let mut found = false;
                for i in 0..MAPPINGS.len() {
                    //port restricted cone
                    if MAPPINGS[i].map_ip == dst_ip && MAPPINGS[i].map_port == dst_port 
                        &&MAPPINGS[i].ext_addr == src_ip && MAPPINGS[i].ext_port == src_port
                    
                    //restricted cone
                    // if MAPPINGS[i].map_ip == dst_ip && MAPPINGS[i].map_port == dst_port && MAPPINGS[i].ext_addr == src_ip 
                    
                    //fullcone
                    // if MAPPINGS[i].map_ip == dst_ip && MAPPINGS[i].map_port == dst_port 
                    {
                        found = true;
                        range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
                        range.min_addr.ip = MAPPINGS[i].int_addr.to_be();
                        range.max_addr.ip = MAPPINGS[i].int_addr.to_be();
                        range.min_proto.udp.port = MAPPINGS[i].int_port.to_be();
                        range.max_proto = range.min_proto;

                        
                        (*regs).__bindgen_anon_1.verdict.code = bindings::nf_nat_setup_info(ct, &range, HOOK2MANIP(hooknum) as i32);
                        break;
                    }
                }
                if !found {
                    // (*regs).__bindgen_anon_1.verdict.code = NFT_CONTINUE;
                }
            }
            nf_inet_hooks_NF_INET_POST_ROUTING => {
                let src_ip = ct_tuple_origin.src.u3.ip.to_be();
                let src_port = ct_tuple_origin.src.u.udp.port.to_be();
                let dst_ip = ct_tuple_origin.dst.u3.ip.to_be();
                let dst_port = ct_tuple_origin.dst.u.udp.port.to_be();

                // pr_err!("nft_prcone: OUTBOUND SNAT from {}:{} to {}:{}\n",
                //     Ipv4Addr::from_bits(src_ip), src_port,
                //     Ipv4Addr::from_bits(dst_ip), dst_port);
                    
                let map_ip = if !out.is_null() { get_device_ip(&*out) } else { 0 };
                let map_port = get_proper_port(src_port);

                // pr_err!("map {}:{}\n", Ipv4Addr::from_bits(map_ip), map_port);
                range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
                range.min_addr.ip = map_ip;
                range.max_addr.ip = map_ip;
                range.min_proto.udp.port = map_port;
                range.max_proto = range.min_proto;

                let mut exists = false;
                for i in 0..MAPPINGS.len() {
                    if MAPPINGS[i].int_addr == src_ip && MAPPINGS[i].int_port == src_port {
                        exists = true;
                        break;
                    }
                }
                if !exists {
                    MAPPINGS.push(NatMapping {
                        int_addr: src_ip,
                        int_port: src_port,
                        map_ip: map_ip.to_be(),
                        map_port: map_port.to_be(),
                        ext_addr: dst_ip,
                        ext_port: dst_port,
                    }, flags::GFP_KERNEL).unwrap_or_else(|_| pr_warn!("Failed to add mapping\n"));
                }

                

                (*regs).__bindgen_anon_1.verdict.code = bindings::nf_nat_setup_info(ct, &range, HOOK2MANIP(hooknum) as i32);
            }
            _ => {
                pr_err!("nothing to do!\n");
            }
        }
    }
}

// 初始化函数
extern "C" fn nft_prcone_init(
    ctx: *const nft_ctx,
    _expr: *const nft_expr,
    _tb: *const *const nlattr,
) -> i32 {
    0
}

// 销毁函数
extern "C" fn nft_prcone_destroy(ctx: *const nft_ctx, _expr: *const nft_expr) {
}

// Netlink 属性策略
fn nft_prcone_policy() -> [nla_policy; 4] {
    let mut policy = [nla_policy::default();  4];
    policy[3].type_ = 3;
    policy[2].type_ = 3;
    policy[2].type_ = 3;
    policy
}

extern "C" fn nft_prcone_validate(ctx: *const nft_ctx, expr: * const nft_expr ) -> i32 {
    // pr_warn!("{} message (level {}) with nft_prcone_validate\n", "Warning", 4);
    let err = unsafe {
        nft_chain_validate_dependency((*ctx).chain,nft_chain_types_NFT_CHAIN_T_NAT)
    };
    if err <0 {
        pr_info!("nft_prcone: NAT chain not found\n");
        return err;
    }
	let err = unsafe {
        nft_chain_validate_hooks((*ctx).chain, (1 << nf_inet_hooks_NF_INET_PRE_ROUTING) | (1 << nf_inet_hooks_NF_INET_POST_ROUTING))
    };
    // pr_info!("validate error is {}\n",err);
    return err;

}

extern "C" fn nft_prcone_dump(skb: *mut sk_buff, expr: *const nft_expr, reset: bool_) ->i32 {
    // pr_warn!("{} message (level {}) with nft_prcone_dump\n", "Warning", 4);
    0
}

#[repr(C)]
struct nft_prcone {
	flags: u32,
    sreg_proto_min: u8,
    sreg_proto_max: u8,
}

// IPv4 表达式操作
fn nft_prcone_ipv4_ops() -> nft_expr_ops {
    nft_expr_ops {
        // type_: unsafe { &NFT_PRCONE_IPV4_TYPE as *const _ },

        //设置为0将会很坑！！！
        size: (core::mem::size_of::<nft_prcone>() as u32) + (core::mem::size_of::<nft_expr>() as u32),
        // size: 0,
        eval: Some(nft_prcone_ipv4_eval),
        init: Some(nft_prcone_init),
        destroy: Some(nft_prcone_destroy),
        dump: Some(nft_prcone_dump),
        validate: Some(nft_prcone_validate), // 未实现
        ..nft_expr_ops::default()
    }
}

// 静态表达式操作和类型定义
// static NFT_PRCONE_IPV4_OPS: nft_expr_ops = nft_prcone_ipv4_ops();

// static mut NFT_PRCONE_IPV4_TYPE: nft_expr_type = nft_expr_type {
//     family: NFPROTO_IPV4 as u32,
//     name: b"prcone\0".as_ptr() as *const i8,
//     ops: unsafe { &NFT_PRCONE_IPV4_OPS as *const _ },
//     policy: nft_prcone_policy().as_ptr() as *const _,
//     maxattr: NFTA_PRCONE_MAX as u32,
//     owner: core::ptr::null_mut(), // 在 init 中设置
//     ..Default::default()
// };