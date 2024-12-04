#![cfg_attr(not(feature = "user"), no_std)]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IngressEvent {
    pub family: u16, // `family` represents the which protocol is encapsulated in the ethernet_frame, eg: IPv4
    pub protocol: u8, // eg: TCP, UDP, etc
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub tc_act: TcAct,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IngressEvent {}

#[cfg(feature = "user")]
impl IngressEvent {
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
            TcAct::Ok => "pass",
            TcAct::Shot => "terminate",
            TcAct::Pipe => "goto_next",
        }
    }
}
