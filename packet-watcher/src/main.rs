use aya::{
    include_bytes_aligned,
    maps::{AsyncPerfEventArray, MapData, MapError},
    programs::{tc, SchedClassifier, TcAttachType},
    util::online_cpus,
    Ebpf,
};
use crossterm::{
    cursor,
    event::{Event, EventStream, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::{FutureExt, StreamExt};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, Cell, Row, Table},
    Terminal,
};
use std::io;

use bytes::BytesMut;
use clap::Parser;
use packet_watcher_common::TrafficEvent;
use pnet_datalink::interfaces;
#[rustfmt::skip]
use log::{debug, warn};
use std::sync::Arc;
use tokio::{
    select,
    sync::{mpsc, Mutex},
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
    let logger = runner.clone();
    // tokio::spawn(async move { logger.display().await });
    logger.display().await?;

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

        drop(bpf);

        Ok(())
    }

    async fn display(&self) -> anyhow::Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let stdout = io::stdout();
        execute!(std::io::stderr(), EnterAlternateScreen, cursor::Hide)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Header row
        let header = Row::new(vec![
            Cell::from("Family"),
            Cell::from("Protocol"),
            Cell::from("Local Addr."),
            Cell::from("Remote Addr."),
            Cell::from("Direction"),
            Cell::from("Action"),
            Cell::from("Reason for Action"),
        ]);

        let widths = [
            Constraint::Percentage(13),
            Constraint::Percentage(13),
            Constraint::Percentage(16),
            Constraint::Percentage(16),
            Constraint::Percentage(13),
            Constraint::Percentage(13),
            Constraint::Percentage(16),
        ];

        // Track scroll position
        let mut scroll_offset = 0;

        // Channel for async updates
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<String>>();

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
                            format!("{} -- {}", data.syn, data.ack),
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
                            format!("{} -- {}", data.syn, data.ack),
                        ];

                        let _ = tx_2.send(log_entry);
                    }
                }
            });
        }

        // List state
        let mut items: Vec<Vec<String>> = Vec::new();

        // for capturing ketboard events
        let mut reader = EventStream::new();

        loop {
            let event = reader.next().fuse();

            select! {
                // Non-blocking receive
                Some(new_item) = rx.recv() => {
                    items.push(new_item);
                }

                // Keyboard event
                maybe_event = event => {
                    match maybe_event {
                        Some(Ok(event)) => {
                            match event {
                                Event::Key(key) => {
                                    match key.code {
                                        KeyCode::Char('q') | KeyCode::Esc => break,
                                        KeyCode::Down => {
                                            if scroll_offset < items.len().saturating_sub(1) {
                                                scroll_offset += 1;
                                            }
                                        }
                                        KeyCode::Up => {
                                            if scroll_offset > 0 {
                                                scroll_offset -= 1;
                                            }
                                        }
                                        _ => {},
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

            // Draw UI
            terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Percentage(100)].as_ref())
                    .split(f.area());

                // Calculate the visible rows based on window height
                let visible_row_count = (chunks[0].height as usize).saturating_sub(3); // Leave space for borders
                let start_index = scroll_offset.min(items.len().saturating_sub(visible_row_count));
                let end_index = (start_index + visible_row_count).min(items.len());

                let table = Table::new(
                    items[start_index..end_index]
                        .iter()
                        .map(|r| Row::new(r.clone())),
                    widths,
                )
                .header(header.clone())
                .block(
                    Block::default()
                        .title("Multi-Column List")
                        .borders(Borders::ALL),
                )
                .column_spacing(1);
                f.render_widget(table, chunks[0]);
            })?;
        }

        // Restore terminal state
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        // cleanup tc qdisc configs
        tc_cleanup();

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
