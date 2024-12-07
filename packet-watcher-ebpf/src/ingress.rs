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

use crate::{process_packet, ptr_at};
use packet_watcher_common::{TcAct, TrafficDirection, TrafficEvent};

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]

pub unsafe fn try_ingress_filter(ctx: TcContext) -> Result<i32, c_long> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| -1)?;
    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN) }.map_err(|_| -1)?;
    let family = eth_hdr.ether_type;
    let protocol = unsafe { *ipv4_hdr }.proto;

    let mut ingress_event: TrafficEvent = core::mem::zeroed();
    ingress_event.family = family as u16;
    ingress_event.protocol = protocol as u8;
    ingress_event.src_addr = u32::from_be(unsafe { *ipv4_hdr }.src_addr);
    ingress_event.dst_addr = u32::from_be(unsafe { *ipv4_hdr }.dst_addr);
    ingress_event.direction = TrafficDirection::Ingress;

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
