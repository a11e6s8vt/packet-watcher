#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketInfo {
    pub packet_len: u32,
    pub skb_len: u32, // Socket Buffer Length
    pub eth_proto: u16,
    pub ip_proto: u8,
    pub src_addr: Option<u32>,
    pub src_port: Option<u32>,
    pub dest_addr: Option<u32>,
    pub dest_port: Option<u32>,
    pub udp_len: Option<u32>,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketInfo {}

impl PacketInfo {
    pub fn new(packet_len: u32, skb_len: u32, eth_proto: u16, ip_proto: u8) -> Self {
        Self {
            packet_len,
            skb_len,
            eth_proto,
            ip_proto,
            src_addr: None,
            src_port: None,
            dest_addr: None,
            dest_port: None,
            udp_len: None,
        }
    }

    pub fn set_src_addr(&mut self, src_addr: Option<u32>) {
        self.src_addr = src_addr;
    }

    pub fn set_src_port(&mut self, src_port: Option<u32>) {
        self.src_port = src_port;
    }

    pub fn set_dest_addr(&mut self, dest_addr: Option<u32>) {
        self.dest_addr = dest_addr;
    }

    pub fn set_dest_port(&mut self, dest_port: Option<u32>) {
        self.dest_port = dest_port;
    }

    pub fn set_udp_len(&mut self, udp_len: Option<u32>) {
        self.udp_len = udp_len;
    }
}
