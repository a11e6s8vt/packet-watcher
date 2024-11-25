#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    cty::c_long,
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};
use aya_log_ebpf::info;
use core::mem;

use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use packet_watcher_common::PacketInfo;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map]
static mut INGRESS_EVENTS: PerfEventArray<PacketInfo> = PerfEventArray::<PacketInfo>::new(0);

#[classifier]
pub fn ingress_filter(ctx: TcContext) -> i32 {
    match unsafe { try_ingress_filter(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

unsafe fn try_ingress_filter(ctx: TcContext) -> Result<i32, c_long> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| -1)?;
    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN) }.map_err(|_| -1)?;
    let packet_len = u16::from_be(unsafe { *ipv4_hdr }.tot_len) as u32;
    let skb_len = ctx.len();
    let eth_proto = eth_hdr.ether_type;
    let ip_proto = unsafe { *ipv4_hdr }.proto;

    let mut packet_info = PacketInfo::new(packet_len, skb_len, eth_proto as u16, ip_proto as u8);
    let src_addr = u32::from_be(unsafe { *ipv4_hdr }.src_addr);
    packet_info.set_src_addr(Some(src_addr));
    let dest_addr = u32::from_be(unsafe { *ipv4_hdr }.dst_addr);
    packet_info.set_dest_addr(Some(dest_addr));

    match (eth_proto, ip_proto) {
        (EtherType::Ipv4, IpProto::Tcp) => {
            let tcp_hdr: *const TcpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }.map_err(|_| -1)?;

            if unsafe { *tcp_hdr }.syn() == 0 || unsafe { *tcp_hdr }.ack() != 0 {
                return Ok(TC_ACT_OK);
            }

            let src_port = u16::from_be(unsafe { *tcp_hdr }.source) as u32;
            let dest_port = u16::from_be(unsafe { *tcp_hdr }.dest) as u32;
            packet_info.set_src_port(Some(src_port));
            packet_info.set_dest_port(Some(dest_port));
        }
        (EtherType::Ipv4, IpProto::Udp) => {
            // UDP Header - src port (2 octets - optional in ipv4)
            // dest port (2 octets), length (2 bytes), checksum (2 bytes - optional in ipv4)
            let udp_hdr: *const UdpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }.map_err(|_| -1)?;

            let src_port = u16::from_be(unsafe { *udp_hdr }.source) as u32;
            let dest_port = u16::from_be(unsafe { *udp_hdr }.dest) as u32;
            packet_info.set_src_port(Some(src_port));
            packet_info.set_dest_port(Some(dest_port));
            packet_info.set_udp_len(Some(unsafe { *udp_hdr }.len as u32));
        }
        // TODO:
        (EtherType::Ipv4, IpProto::Icmp) => {
            let icmp_hdr: *const IcmpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }.map_err(|_| -1)?;
        }
        (_, _) => return Ok(TC_ACT_OK),
    };

    unsafe {
        INGRESS_EVENTS.output(&ctx, &packet_info, 0);
    }

    Ok(TC_ACT_OK)
}

#[classifier]
pub fn egress_filter(ctx: TcContext) -> i32 {
    match unsafe { try_egress_filter(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

unsafe fn try_egress_filter(ctx: TcContext) -> Result<i32, c_long> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| -1)?;
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
