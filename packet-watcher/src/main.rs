use aya::{
    include_bytes_aligned,
    maps::AsyncPerfEventArray,
    programs::{tc, SchedClassifier, TcAttachType},
    util::online_cpus,
    Ebpf,
};

use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use packet_watcher_common::PacketInfo;
#[rustfmt::skip]
use log::{debug, warn};
use std::{arch::x86_64::_SIDD_MASKED_POSITIVE_POLARITY, net::Ipv4Addr};
use tokio::{signal, task};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/packet-watcher"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let _ = tc::qdisc_add_clsact(&opt.iface);

    let ingress_prog: &mut SchedClassifier = ebpf.program_mut("ingress").unwrap().try_into()?;
    ingress_prog.load()?;
    ingress_prog.attach(&opt.iface, TcAttachType::Ingress)?;

    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;

    let cpus = online_cpus().unwrap_or_default();
    let num_cpus = cpus.len();
    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<PacketInfo>()))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for event in buffers.iter_mut().take(events.read) {
                    let ptr = event.as_ptr() as *const PacketInfo;
                    let data = unsafe { ptr.read_unaligned() };

                    let mut log_entry = String::new();
                    log_entry.push_str(&format!(
                        "LOG: LEN: {}, SBK_LEN {}, ETH_PROTO {}, IP_PROTO {}, ",
                        data.packet_len, data.skb_len, data.eth_proto, data.ip_proto
                    ));

                    if data.udp_len.is_some() {
                        log_entry.push_str(&format!("UDP Length {}, ", data.udp_len.unwrap()));
                    }

                    if data.src_addr.is_some() {
                        log_entry.push_str(&format!(
                            "SRC_IP {}, ",
                            Ipv4Addr::from(data.src_addr.unwrap())
                        ));
                    }

                    if data.src_port.is_some() {
                        log_entry.push_str(&format!("SRC_PORT {}, ", data.src_port.unwrap()));
                    }

                    if data.dest_addr.is_some() {
                        log_entry.push_str(&format!(
                            "DEST_IP {}, ",
                            Ipv4Addr::from(data.dest_addr.unwrap())
                        ));
                    }

                    if data.dest_port.is_some() {
                        log_entry.push_str(&format!("DEST_PORT {}", data.dest_port.unwrap()));
                    }

                    // println!(
                    //     "LOG: LEN {}, SBK_LEN {}, UDP_LEN {}, SRC_IP {}, SRC_PORT {}, ETH_PROTO 0x{:X}, IP_PROTO {}, DEST_IP {}, DEST_PORT {} ",
                    //     data.packet_len,
                    //     data.skb_len,
                    //     data.udp_len,
                    //     Ipv4Addr::from(data.src_addr),
                    //     data.src_port,
                    //     data.eth_proto,
                    //     data.ip_proto,
                    //     Ipv4Addr::from(data.dest_addr),
                    //     data.dest_port,
                    // );
                    println!("{}", log_entry);
                }
            }
        });
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
