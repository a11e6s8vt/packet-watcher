#![cfg_attr(not(feature = "user"), no_std)]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrafficEvent {
    pub family: u16, // `family` represents the which protocol is encapsulated in the ethernet_frame, eg: IPv4
    pub protocol: u8, // eg: TCP, UDP, etc
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub direction: TrafficDirection,
    pub tc_act: TcAct,
    pub syn: u16,
    pub ack: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TrafficEvent {}

#[cfg(feature = "user")]
impl TrafficEvent {
    pub fn src_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.src_addr).to_string()
    }

    pub fn dst_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.dst_addr).to_string()
    }

    pub fn family(&self) -> &'static str {
        match self.family {
            1 => "ARP",
            8 => "IPv4",
            24 => "LOOP",
            56 => "IPv6",
            _ => "Unknown",
        }
    }

    pub fn protocol(&self) -> &'static str {
        match self.protocol {
            1 => "ICMP",
            4 => "IPv4",
            6 => "TCP",
            17 => "UDP",
            41 => "IPv6",
            _ => "Unknown",
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum TcAct {
    Ok,
    Shot,
    Pipe,
}

impl TcAct {
    pub fn format(&self) -> &'static str {
        match self {
            TcAct::Ok => "Accept",
            TcAct::Shot => "Reject",
            TcAct::Pipe => "Accept",
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum TrafficDirection {
    Ingress,
    Egress,
}

impl TrafficDirection {
    pub fn format(&self) -> &'static str {
        match self {
            TrafficDirection::Ingress => "Incoming",
            TrafficDirection::Egress => "Outgoing",
        }
    }
}
