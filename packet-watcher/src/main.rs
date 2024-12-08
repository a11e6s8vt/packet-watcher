mod tui;

use aya::{
    include_bytes_aligned,
    maps::{AsyncPerfEventArray, MapData, MapError},
    programs::{tc, SchedClassifier, TcAttachType},
    util::online_cpus,
    Ebpf,
};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use tui::{draw_ui, App};

use futures::{FutureExt, StreamExt};

use bytes::BytesMut;
use clap::Parser;
use packet_watcher_common::TrafficEvent;
use pnet_datalink::interfaces;
#[rustfmt::skip]
use log::{debug, warn};
use std::sync::Arc;
use tokio::{
    select,
    sync::{
        mpsc::{self, UnboundedSender},
        Mutex,
    },
    task,
};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _opt = Opt::parse();
    env_logger::init();

    let all_interfaces = interfaces();

    // Search for the default interface - the one that is
    // up, not loopback and has an IP.
    let default_interface = all_interfaces
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());

    if default_interface.is_none() {
        println!("Error while finding the default interface.");
        return Ok(());
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
    let data_processor = runner.clone();

    // Channel for async updates
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<String>>();
    tokio::spawn(async move { data_processor.process_kernel_bpf_data(tx.clone()).await });

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // for capturing ketboard events
    let mut reader = EventStream::new();

    // Create app and run it
    let mut app = App::new();
    loop {
        let event = reader.next().fuse();
        terminal.draw(|f| draw_ui(f, &mut app))?;
        select! {
            // Non-blocking receive
            Some(new_item) = rx.recv() => {
                app.add_row(new_item);
            }

            // Keyboard event
            maybe_event = event => {
                match maybe_event {
                    Some(Ok(event)) => {
                        match event {
                            Event::Key(key) => {
                                match key.code {
                                    KeyCode::Char('q') => break,
                                    KeyCode::Down => app.next(),
                                    KeyCode::Up => app.previous(),
                                    _ => {}
                                };
                            }
                            Event::Resize(_x, _y) => {}
                            _ => {}

                        }
                    }
                    Some(Err(e)) => println!("Error: {:?}\r", e),
                    None => {},
                }

            }
        };
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    tc_cleanup();
    Ok(())
}

struct BpfRunner {
    ebpf: Arc<Mutex<Ebpf>>,
}

impl BpfRunner {
    pub fn new() -> anyhow::Result<Self> {
        let ebpf = Arc::new(Mutex::new(Ebpf::load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/packet-watcher"
        )))?));
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
                let _ = tc::qdisc_add_clsact(iface);
                let program: &mut SchedClassifier =
                    bpf.program_mut("ingress_filter").unwrap().try_into()?;
                program.attach(iface, TcAttachType::Ingress)?;

                let program: &mut SchedClassifier =
                    bpf.program_mut("egress_filter").unwrap().try_into()?;
                program.attach(iface, TcAttachType::Egress)?;
            }
        }

        // Example code to add IPs to the block_list in the kernerl side
        // let block_list = bpf.map_mut("BLOCK_LIST").unwrap();
        // block_list.insert(&Ipv4Addr::new(192, 168, 1, 1).into(), &0, 0)?;
        // block_list.insert(&Ipv4Addr::new(192, 168, 1, 2).into(), &0, 0)?;

        drop(bpf);

        Ok(())
    }

    async fn process_kernel_bpf_data(
        &self,
        tx: UnboundedSender<Vec<String>>,
    ) -> anyhow::Result<()> {
        let mut perf_array_ingress = self.read_ingress_events().await?;
        let mut perf_array_egress = self.read_egress_events().await?;

        let cpus = online_cpus().unwrap_or_default();
        let num_cpus = cpus.len();

        for cpu_id in cpus {
            let tx_1 = tx.clone();
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

                        let log_entry = vec![
                            data.family().to_string(),
                            data.protocol().to_string(),
                            format!("{}:{}", data.src_addr(), data.src_port),
                            format!("{}:{}", data.dst_addr(), data.dst_port),
                            data.direction.format().to_string(),
                            data.tc_act.format().to_string(),
                        ];

                        let _ = tx_1.send(log_entry);
                    }
                }
            });

            let tx_2 = tx.clone();
            task::spawn(async move {
                let mut buffers = (0..num_cpus)
                    .map(|_| BytesMut::with_capacity(std::mem::size_of::<TrafficEvent>()))
                    .collect::<Vec<_>>();

                loop {
                    let events = egress_buf.read_events(&mut buffers).await.unwrap();
                    for event in buffers.iter_mut().take(events.read) {
                        let ptr = event.as_ptr() as *const TrafficEvent;
                        let data = unsafe { ptr.read_unaligned() };

                        let log_entry = vec![
                            data.family().to_string(),
                            data.protocol().to_string(),
                            format!("{}:{}", data.src_addr(), data.src_port),
                            format!("{}:{}", data.dst_addr(), data.dst_port),
                            data.direction.format().to_string(),
                            data.tc_act.format().to_string(),
                        ];

                        let _ = tx_2.send(log_entry);
                    }
                }
            });
        }

        Ok(())
    }
}

pub fn tc_cleanup() {
    for interface in interfaces() {
        if interface.is_up() && !interface.is_loopback() && !interface.ips.is_empty() {
            let iface = interface.name.as_str();
            // tc::qdisc_detach_program(, , ) doesn't work unfortunately
            // match tc::qdisc_detach_program(iface, TcAttachType::Ingress, "ingress_filter") {
            //     Ok(_) => println!("TC qdisc configuration removed from {}", iface),
            //     Err(e) => {
            //         eprintln!(
            //             "TC qdisc config couldn't be removed from {} with error {}",
            //             iface, e
            //         );
            //         std::process::exit(1);
            //     }
            // }

            // match tc::qdisc_detach_program(iface, TcAttachType::Egress, "egress_filter") {
            //     Ok(_) => println!("TC qdisc configuration removed from {}", iface),
            //     Err(e) => {
            //         eprintln!(
            //             "TC qdisc config couldn't be removed from {} with error {}",
            //             iface, e
            //         );
            //         std::process::exit(1);
            //     }
            // }
            let _ = std::process::Command::new("tc")
                .args(&vec!["qdisc", "del", "dev", iface, "clsact"])
                .output();
        }
    }
}
