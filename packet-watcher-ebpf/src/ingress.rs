use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_PIPE, TC_ACT_SHOT},
    cty::c_long,
    helpers::{bpf_ktime_get_ns, bpf_map_lookup_elem, bpf_map_update_elem},
    macros::map,
    maps::HashMap,
    programs::TcContext,
};

use aya_log_ebpf::info;

use core::time::Duration;

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
#[derive(Clone, Copy)]
#[repr(C)]
struct TcpSynEvent {
    pub count: u64,
    pub time: u64,
}

const WINDOW_SIZE: u64 = 10;
const SYN_THRESHOLD: u64 = 100;
const SYN_TO_ACK_RATIO_THRESHOLD: u64 = 3;

#[map]
static mut SYN_COUNT: HashMap<u32, TcpSynEvent> = HashMap::with_max_entries(1024, 0);

#[map]
static mut SYN_ACK_COUNT: HashMap<u32, TcpSynEvent> = HashMap::with_max_entries(1024, 0);

unsafe fn track_syn_event(ingress_event: &mut TrafficEvent, ack_flag: u16) -> Result<i32, c_long> {
    let src_ip = ingress_event.src_addr;
    let now_ns = bpf_ktime_get_ns();

    let syn_e = unsafe {
        SYN_COUNT
            .get(&src_ip)
            .unwrap_or(&TcpSynEvent { count: 0, time: 0 })
    };

    let syn_ack_e = unsafe {
        SYN_ACK_COUNT
            .get(&src_ip)
            .unwrap_or(&TcpSynEvent { count: 0, time: 0 })
    };

    let last_event_time = syn_e.time;
    let mut new_syn_e: TcpSynEvent = core::mem::zeroed();

    if last_event_time == 0 {
        new_syn_e.count = 1;
        new_syn_e.time = now_ns;
        let _ = unsafe { SYN_COUNT.insert(&src_ip, &new_syn_e, 0) };
        ingress_event.tc_act = TcAct::Pipe;
        return Ok(TC_ACT_PIPE);
    } else {
        let ratio = syn_e.count / (syn_ack_e.count + 1); // +1 to avoid division by zero
        let elapsed = now_ns - last_event_time;
        if elapsed > WINDOW_SIZE
            && (syn_e.count > SYN_THRESHOLD || ratio > SYN_TO_ACK_RATIO_THRESHOLD)
        {
            ingress_event.tc_act = TcAct::Shot;
        }
    }

    if ack_flag != 0 {
        let mut new_syn_ack_e: TcpSynEvent = core::mem::zeroed();
        let e = SYN_ACK_COUNT.get(&src_ip);
        if e.is_some() {
            let e = e.unwrap();
            new_syn_ack_e.count = e.count + 1;
        } else {
            new_syn_ack_e.count = 1;
        }
        new_syn_ack_e.time = now_ns;
        let _ = unsafe { SYN_ACK_COUNT.insert(&src_ip, &new_syn_ack_e, 0) };
    }

    Ok(0)
}

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

            let ack_flag = unsafe { *tcp_hdr }.ack();
            let syn_flag = unsafe { *tcp_hdr }.syn();

            ingress_event.syn = syn_flag;
            ingress_event.ack = ack_flag;

            ingress_event.src_port = u16::from_be(unsafe { *tcp_hdr }.source);
            ingress_event.dst_port = u16::from_be(unsafe { *tcp_hdr }.dest);

            // Accept and proceed to the next packet unless "the SYN flag is set and ACK flag not set"
            if syn_flag == 0 && ack_flag != 0 {
                return Ok(TC_ACT_PIPE);
            }

            if syn_flag != 0 {
                let _ = track_syn_event(&mut ingress_event, ack_flag);
            }

            if ingress_event.tc_act == 0 {
                ingress_event.tc_act = TcAct::Pipe;
            }

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
