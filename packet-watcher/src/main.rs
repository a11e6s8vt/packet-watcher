use aya::{
    include_bytes_aligned,
    maps::AsyncPerfEventArray,
    programs::{tc, SchedClassifier, TcAttachType},
    util::online_cpus,
};

use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use packet_watcher_common::IngressEvent;
use pnet_datalink::interfaces;
#[rustfmt::skip]
use log::{debug, warn};
use std::sync::Arc;
use tokio::{signal, sync::Mutex, task};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::init();

    let all_interfaces = interfaces();

    // Search for the default interface - the one that is
    // up, not loopback and has an IP.
    let default_interface = all_interfaces
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());

    let interface_name = match default_interface {
        Some(interface) => {
            println!("Found default interface with [{}].", interface.name.clone());
            interface.name.clone()
        }
        None => {
            println!("Error while finding the default interface.");
            return Ok(());
        }
    };

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
    let ebpf = Arc::new(Mutex::new(aya::Ebpf::load(aya::include_bytes_aligned!(
        concat!(env!("OUT_DIR"), "/packet-watcher")
    ))?));

    let mut bpf = ebpf.lock().await;
    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let _ = tc::qdisc_add_clsact(&interface_name);

    let ingress_prog: &mut SchedClassifier =
        bpf.program_mut("ingress_filter").unwrap().try_into()?;
    ingress_prog.load()?;

    ingress_prog.attach(&interface_name, TcAttachType::Ingress)?;

    // let egress_prog: &mut SchedClassifier =
    //     ebpf.program_mut("egress_filter").unwrap().try_into()?;
    // egress_prog.load()?;
    // egress_prog.attach(&opt.iface, TcAttachType::Egress)?;

    let mut perf_array_ingress =
        AsyncPerfEventArray::try_from(bpf.take_map("INGRESS_EVENTS").unwrap())?;

    drop(bpf);
    let cpus = online_cpus().unwrap_or_default();
    let num_cpus = cpus.len();
    for cpu_id in cpus {
        let mut buf = perf_array_ingress.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<IngressEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for event in buffers.iter_mut().take(events.read) {
                    let ptr = event.as_ptr() as *const IngressEvent;
                    let data = unsafe { ptr.read_unaligned() };

                    let mut log_entry = String::new();
                    log_entry.push_str(&format!(
                        "FAMILY: {}, PROTOCOL: {}, SRC_ADDR: {}:{}, DST_ADDR: {}:{}, PACKET_ACTION: {}",
                        data.family(),
                        data.protocol(),
                        data.src_addr(),
                        data.src_port,
                        data.dst_addr(),
                        data.dst_port,
                        data.tc_act.format(),
                    ));

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
