#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_PIPE, TC_ACT_SHOT},
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

use packet_watcher_common::{TcAct, TrafficEvent};

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
static mut INGRESS_EVENTS: PerfEventArray<TrafficEvent> = PerfEventArray::<TrafficEvent>::new(0);

#[map]
static mut EGRESS_EVENTS: PerfEventArray<TrafficEvent> = PerfEventArray::<TrafficEvent>::new(0);

enum TrafficDirection {
    Ingress,
    Egress,
}

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
    let family = eth_hdr.ether_type;
    let protocol = unsafe { *ipv4_hdr }.proto;

    let mut ingress_event: TrafficEvent = core::mem::zeroed();
    ingress_event.family = family as u16;
    ingress_event.protocol = protocol as u8;
    ingress_event.src_addr = u32::from_be(unsafe { *ipv4_hdr }.src_addr);
    ingress_event.dst_addr = u32::from_be(unsafe { *ipv4_hdr }.dst_addr);

    match (family, protocol) {
        (EtherType::Ipv4, IpProto::Tcp) => {
            let tcp_hdr: *const TcpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }.map_err(|_| -1)?;

            if unsafe { *tcp_hdr }.syn() == 0 || unsafe { *tcp_hdr }.ack() != 0 {
                return Ok(TC_ACT_OK);
            }

            ingress_event.src_port = u16::from_be(unsafe { *tcp_hdr }.source);
            ingress_event.dst_port = u16::from_be(unsafe { *tcp_hdr }.dest);
            return process_packet(
                &ctx,
                TcAct::Pipe,
                &mut ingress_event,
                TrafficDirection::Ingress,
            );
        }
        (EtherType::Ipv4, IpProto::Udp) => {
            // UDP Header - src port (2 octets - optional in ipv4)
            // dest port (2 octets), length (2 bytes), checksum (2 bytes - optional in ipv4)
            let udp_hdr: *const UdpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }.map_err(|_| -1)?;

            ingress_event.src_port = u16::from_be(unsafe { *udp_hdr }.source);
            ingress_event.dst_port = u16::from_be(unsafe { *udp_hdr }.dest);
            return process_packet(
                &ctx,
                TcAct::Pipe,
                &mut ingress_event,
                TrafficDirection::Ingress,
            );
        }
        // TODO:
        (EtherType::Ipv4, IpProto::Icmp) => {
            let icmp_hdr: *const IcmpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }.map_err(|_| -1)?;
            unsafe { *icmp_hdr }.type_;
            return process_packet(
                &ctx,
                TcAct::Shot,
                &mut ingress_event,
                TrafficDirection::Ingress,
            );
        }
        (_, _) => return Ok(TC_ACT_OK),
    }
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
    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN) }.map_err(|_| -1)?;
    let family = eth_hdr.ether_type;
    let protocol = unsafe { *ipv4_hdr }.proto;

    let mut egress_event: TrafficEvent = core::mem::zeroed();
    egress_event.family = family as u16;
    egress_event.protocol = protocol as u8;
    egress_event.src_addr = u32::from_be(unsafe { *ipv4_hdr }.src_addr);
    egress_event.dst_addr = u32::from_be(unsafe { *ipv4_hdr }.dst_addr);

    match (family, protocol) {
        (EtherType::Ipv4, IpProto::Tcp) => {
            let tcp_hdr: *const TcpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }.map_err(|_| -1)?;

            if unsafe { *tcp_hdr }.syn() == 0 || unsafe { *tcp_hdr }.ack() != 0 {
                return Ok(TC_ACT_OK);
            }

            egress_event.src_port = u16::from_be(unsafe { *tcp_hdr }.source);
            egress_event.dst_port = u16::from_be(unsafe { *tcp_hdr }.dest);
            return process_packet(
                &ctx,
                TcAct::Pipe,
                &mut egress_event,
                TrafficDirection::Egress,
            );
        }
        (EtherType::Ipv4, IpProto::Udp) => {
            // UDP Header - src port (2 octets - optional in ipv4)
            // dest port (2 octets), length (2 bytes), checksum (2 bytes - optional in ipv4)
            let udp_hdr: *const UdpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }.map_err(|_| -1)?;

            egress_event.src_port = u16::from_be(unsafe { *udp_hdr }.source);
            egress_event.dst_port = u16::from_be(unsafe { *udp_hdr }.dest);
            return process_packet(
                &ctx,
                TcAct::Pipe,
                &mut egress_event,
                TrafficDirection::Egress,
            );
        }
        // TODO:
        (EtherType::Ipv4, IpProto::Icmp) => {
            let icmp_hdr: *const IcmpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }.map_err(|_| -1)?;
            unsafe { *icmp_hdr }.type_;
            return process_packet(
                &ctx,
                TcAct::Shot,
                &mut egress_event,
                TrafficDirection::Egress,
            );
        }
        (_, _) => return Ok(TC_ACT_OK),
    }
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

unsafe fn process_packet(
    ctx: &TcContext,
    tc_act: TcAct,
    event: &mut TrafficEvent,
    direction: TrafficDirection,
) -> Result<i32, c_long> {
    event.tc_act = tc_act;

    match direction {
        TrafficDirection::Ingress => unsafe { INGRESS_EVENTS.output(ctx, event, 0) },
        TrafficDirection::Egress => unsafe { EGRESS_EVENTS.output(ctx, event, 0) },
    }

    Ok(match tc_act {
        TcAct::Ok => TC_ACT_OK,
        TcAct::Shot => TC_ACT_SHOT,
        TcAct::Pipe => TC_ACT_PIPE,
    })
}
