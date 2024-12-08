use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_PIPE, TC_ACT_SHOT},
    cty::c_long,
    helpers::{bpf_ktime_get_ns, bpf_printk},
    macros::map,
    maps::HashMap,
    programs::TcContext,
};

use aya_log_ebpf::info;

use core::{ffi::CStr, ops::Div, time::Duration};

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

const WINDOW_SIZE: u64 = 1_000_000_000; // One second window in NS
const SYN_THRESHOLD: u64 = 100;
const SYN_TO_ACK_RATIO_THRESHOLD: u64 = 3;

#[map]
static mut SYN_COUNT: HashMap<u32, [u64; 2usize]> = HashMap::with_max_entries(1024, 0);

#[map]
static mut SYN_ACK_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

unsafe fn track_syn_event(src_ip: u32, ack_flag: u16) -> Result<TcAct, c_long> {
    let now_ns = bpf_ktime_get_ns();

    let last_syn_event = unsafe { SYN_COUNT.get(&src_ip).unwrap_or(&[0, 0]) };
    let ack_count = unsafe { SYN_ACK_COUNT.get(&src_ip).unwrap_or(&0) };

    if ack_flag != 0 {
        let _ = unsafe { SYN_ACK_COUNT.insert(&src_ip, &(ack_count + 1), 0) };
    }

    let elapsed = now_ns - last_syn_event.get(0).unwrap();
    let mut new_event = [last_syn_event[0], last_syn_event[1]];

    if elapsed > WINDOW_SIZE {
        new_event[0] = now_ns;
        new_event[1] = 1;
    } else {
        new_event[1] += 1;
    }

    if new_event[1] > SYN_THRESHOLD {
        return Ok(TcAct::Shot);
    }

    unsafe {
        SYN_COUNT
            .insert(&src_ip, &new_event, 0)
            .map_err(|_| TcAct::Unspec);
    };

    Ok(TcAct::Pipe)
}

// unsafe fn track_syn_event(src_ip: u32, ack_flag: u16) -> Result<TcAct, c_long> {
//     let now_ns = bpf_ktime_get_ns();

//     let last_syn_event = unsafe {
//         SYN_COUNT
//             .get(&src_ip)
//             .unwrap_or(&TcpSynEvent { count: 0, time: 0 })
//     };
//     let ack_count = unsafe { SYN_ACK_COUNT.get(&src_ip).unwrap_or(&0) };

//     // let syn_ack_e = unsafe {
//     //     SYN_ACK_COUNT
//     //         .get(&src_ip)
//     //         .unwrap_or(&TcpSynEvent { count: 0, time: 0 })
//     // };

//     // let last_event_time = window[0];

//     if ack_flag != 0 {
//         let _ = unsafe { SYN_ACK_COUNT.insert(&src_ip, &(ack_count + 1), 0) };
//     }

//     // First entry for this src_ip in the map
//     if last_syn_event.time == 0 {
//         let _ = unsafe {
//             SYN_COUNT.insert(
//                 &src_ip,
//                 &TcpSynEvent {
//                     count: 1,
//                     time: now_ns,
//                 },
//                 0,
//             )
//         };

//         return Ok(TcAct::Ok);
//     }

//     let elapsed = now_ns - last_syn_event.time;

//     if elapsed > WINDOW_SIZE {
//         let ratio = last_syn_event.count.checked_div_euclid(*ack_count);
//         if ratio.is_some_and(|ratio| ratio > SYN_TO_ACK_RATIO_THRESHOLD)
//             && last_syn_event.count > SYN_THRESHOLD
//         {
//             let _ = unsafe {
//                 SYN_COUNT.insert(
//                     &src_ip,
//                     &TcpSynEvent {
//                         count: 1,
//                         time: now_ns,
//                     },
//                     0,
//                 )
//             };

//             let _ = unsafe { SYN_ACK_COUNT.insert(&src_ip, &0, 0) };
//             return Ok(TcAct::Shot);
//         }
//     } else {
//         let _ = unsafe {
//             SYN_COUNT.insert(
//                 &src_ip,
//                 &TcpSynEvent {
//                     count: last_syn_event.count + 1,
//                     time: last_syn_event.time,
//                 },
//                 0,
//             )
//         };
//     }

//     Ok(TcAct::Ok)
// }

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

            // Setting TcAct to TC_ACT_OK as a default value
            ingress_event.tc_act = TcAct::Ok;

            if syn_flag != 0 {
                if let Ok(tc_act) = track_syn_event(ingress_event.src_addr, ack_flag) {
                    ingress_event.tc_act = tc_act;
                } else {
                    // let msg = CStr::from_bytes_until_nul(b"SYN packet detected: %u\0").unwrap();
                    unsafe {
                        bpf_printk!(b"{}", ingress_event.src_addr);
                    }
                }
            }

            return process_packet(&ctx, &mut ingress_event, TrafficDirection::Ingress);
        }
        (EtherType::Ipv4, IpProto::Udp) => {
            // UDP Header - src port (2 octets - optional in ipv4)
            // dest port (2 octets), length (2 bytes), checksum (2 bytes - optional in ipv4)
            let udp_hdr: *const UdpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }.map_err(|_| -1)?;

            ingress_event.src_port = u16::from_be(unsafe { *udp_hdr }.source);
            ingress_event.dst_port = u16::from_be(unsafe { *udp_hdr }.dest);

            // Setting TcAct to TC_ACT_OK as a default value
            ingress_event.tc_act = TcAct::Ok;

            return process_packet(&ctx, &mut ingress_event, TrafficDirection::Ingress);
        }
        // TODO:
        (EtherType::Ipv4, IpProto::Icmp) => {
            let icmp_hdr: *const IcmpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }.map_err(|_| -1)?;
            unsafe { *icmp_hdr }.type_;

            // Setting TcAct to TC_ACT_OK as a default value
            ingress_event.tc_act = TcAct::Ok;

            return process_packet(&ctx, &mut ingress_event, TrafficDirection::Ingress);
        }
        (_, _) => return Ok(TC_ACT_OK),
    }
}
