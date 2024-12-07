use aya::{
    include_bytes_aligned,
    maps::{AsyncPerfEventArray, MapData, MapError},
    programs::{perf_event, tc, SchedClassifier, TcAttachType},
    util::online_cpus,
    Ebpf,
};
use crossterm::{
    cursor,
    event::{self, Event, EventStream, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::{FutureExt, StreamExt};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Cell, List, ListItem, Row, Table},
    Terminal,
};
use std::{io, time::Duration};

use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use packet_watcher_common::TrafficEvent;
use pnet_datalink::interfaces;
#[rustfmt::skip]
use log::{debug, warn};
use std::sync::Arc;
use tokio::{
    select, signal,
    sync::{mpsc, Mutex},
    task, time,
};

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

    let runner = Arc::new(BpfRunner::new()?);
    runner.load().await?;
    let logger = runner.clone();
    tokio::spawn(async move { logger.display().await });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

struct BpfRunner {
    ebpf: Arc<Mutex<Ebpf>>,
}

impl BpfRunner {
    pub fn new() -> anyhow::Result<Self> {
        let ebpf = Arc::new(Mutex::new(aya::Ebpf::load(aya::include_bytes_aligned!(
            concat!(env!("OUT_DIR"), "/packet-watcher")
        ))?));
        Ok(Self { ebpf })
    }

    pub async fn read_ingress_events(
        &self,
    ) -> anyhow::Result<AsyncPerfEventArray<MapData>, MapError> {
        let mut bpf = self.ebpf.lock().await;
        let perf_event_arr = AsyncPerfEventArray::try_from(bpf.take_map("INGRESS_EVENTS").unwrap());
        drop(bpf);
        perf_event_arr
    }

    pub async fn read_egress_events(
        &self,
    ) -> anyhow::Result<AsyncPerfEventArray<MapData>, MapError> {
        let mut bpf = self.ebpf.lock().await;
        let perf_event_arr = AsyncPerfEventArray::try_from(bpf.take_map("EGRESS_EVENTS").unwrap());
        drop(bpf);
        perf_event_arr
    }

    pub async fn load(&self) -> anyhow::Result<()> {
        let mut bpf = self.ebpf.lock().await;
        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }

        let program: &mut SchedClassifier =
            bpf.program_mut("ingress_filter").unwrap().try_into()?;
        program.load()?;

        let program: &mut SchedClassifier = bpf.program_mut("egress_filter").unwrap().try_into()?;
        program.load()?;

        drop(bpf);
        self.attach().await?;

        Ok(())
    }

    async fn attach(&self) -> anyhow::Result<()> {
        let mut bpf = self.ebpf.lock().await;
        // Search for the default interface - the one that is
        // up, not loopback and has an IP.
        for interface in interfaces() {
            if interface.is_up() && !interface.is_loopback() && !interface.ips.is_empty() {
                let iface = interface.name.as_str();
                println!("Found default interface with [{}].", iface);
                let _ = tc::qdisc_add_clsact(iface);
                println!("Found default interface with [{}].", iface);
                let program: &mut SchedClassifier =
                    bpf.program_mut("ingress_filter").unwrap().try_into()?;
                match program.attach(iface, TcAttachType::Ingress) {
                    Ok(_) => println!("Success"),
                    Err(e) => println!("{:?}", e),
                };

                let program: &mut SchedClassifier =
                    bpf.program_mut("egress_filter").unwrap().try_into()?;
                program.attach(&iface, TcAttachType::Egress)?;
            }
        }

        drop(bpf);

        Ok(())
    }

    async fn display(&self) -> anyhow::Result<()> {
        let mut perf_array_ingress = self.read_ingress_events().await?;
        let mut perf_array_egress = self.read_egress_events().await?;

        let cpus = online_cpus().unwrap_or_default();
        let num_cpus = cpus.len();
        for cpu_id in cpus {
            let mut ingress_buf = perf_array_ingress.open(cpu_id, None)?;
            let mut egress_buf = perf_array_egress.open(cpu_id, None)?;

            task::spawn(async move {
                let mut buffers = (0..num_cpus)
                    .map(|_| BytesMut::with_capacity(std::mem::size_of::<TrafficEvent>()))
                    .collect::<Vec<_>>();

                loop {
                    let events = ingress_buf.read_events(&mut buffers).await.unwrap();
                    for event in buffers.iter_mut().take(events.read) {
                        let ptr = event.as_ptr() as *const TrafficEvent;
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

            task::spawn(async move {
                let mut buffers = (0..num_cpus)
                    .map(|_| BytesMut::with_capacity(std::mem::size_of::<TrafficEvent>()))
                    .collect::<Vec<_>>();

                loop {
                    let events = egress_buf.read_events(&mut buffers).await.unwrap();
                    for event in buffers.iter_mut().take(events.read) {
                        let ptr = event.as_ptr() as *const TrafficEvent;
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
        Ok(())
    }
}
