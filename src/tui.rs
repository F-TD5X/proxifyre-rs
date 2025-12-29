use crate::router::SocksLocalRouter;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::collections::VecDeque;
use std::io::stdout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

pub struct TuiState {
    pub logs: Arc<Mutex<Vec<String>>>,
    pub router: Arc<SocksLocalRouter>,
    shutdown: AtomicBool,
    cpu_sampler: Mutex<CpuSampler>,
    traffic_sampler: Mutex<TrafficSampler>,
}

impl TuiState {
    pub fn new(router: Arc<SocksLocalRouter>, logs: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            logs,
            router,
            shutdown: AtomicBool::new(false),
            cpu_sampler: Mutex::new(CpuSampler::new()),
            traffic_sampler: Mutex::new(TrafficSampler::new(Duration::from_secs(5))),
        }
    }

    pub fn format_bytes(&self, bytes: u64) -> String {
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 {
            format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    pub fn should_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    pub fn format_time(&self, duration: Duration) -> String {
        let total_secs = duration.as_secs();
        let hours = total_secs / 3600;
        let minutes = (total_secs % 3600) / 60;
        let seconds = total_secs % 60;
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    }

    pub fn get_process_usage(&self) -> (f64, u64) {
        let cpu = self
            .cpu_sampler
            .lock()
            .unwrap()
            .sample()
            .clamp(0.0, 100.0);
        let mem = get_process_memory_bytes().unwrap_or(0);
        (cpu, mem)
    }

    pub fn get_traffic_rates(&self, bytes_sent: u64, bytes_received: u64) -> (f64, f64) {
        self.traffic_sampler
            .lock()
            .unwrap()
            .sample(bytes_sent, bytes_received)
    }

    pub fn format_rate(&self, bytes_per_sec: f64) -> String {
        let rounded = bytes_per_sec.round().max(0.0) as u64;
        format!("{}/s", self.format_bytes(rounded))
    }
}

pub struct Tui {
    state: Arc<TuiState>,
}

impl Tui {
    pub fn new(state: Arc<TuiState>) -> Self {
        Self { state }
    }

    pub fn run(&mut self) -> Result<(), std::io::Error> {
        enable_raw_mode()?;
        let stdout = stdout();
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        terminal.clear()?;

        loop {
            if self.state.should_shutdown() {
                break;
            }

            terminal.draw(|frame| self.draw(frame))?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        if key.code == KeyCode::Char('c')
                            && key.modifiers.contains(event::KeyModifiers::CONTROL)
                        {
                            self.state.request_shutdown();
                            break;
                        }
                        if key.code == KeyCode::Char('q') {
                            self.state.request_shutdown();
                            break;
                        }
                    }
                }
            }
        }

        disable_raw_mode()?;
        terminal.show_cursor()?;
        Ok(())
    }

    fn draw(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(1),
                Constraint::Length(1),
            ])
            .split(frame.area());

        self.draw_logs(frame, chunks[0]);
        self.draw_status_bar(frame, chunks[1]);
    }

    fn draw_logs(&self, frame: &mut Frame, area: Rect) {
        let logs = self.state.logs.lock().unwrap();
        let log_items: Vec<ListItem> = logs
            .iter()
            .rev()
            .take(area.height as usize)
            .map(|log| ListItem::new(log.clone()))
            .collect();

        let list = List::new(log_items)
            .block(Block::bordered().title(" Logs "))
            .style(Style::default().fg(Color::White));

        frame.render_widget(list, area);
    }

    fn draw_status_bar(&self, frame: &mut Frame, area: Rect) {
        let tcp_count = self.state.router.get_tcp_connection_count();
        let udp_count = self.state.router.get_udp_connection_count();
        let bytes_sent = self.state.router.get_bytes_sent();
        let bytes_received = self.state.router.get_bytes_received();
        let running_time = self.state.router.get_running_time();
        let (cpu_percent, mem_bytes) = self.state.get_process_usage();
        let (up_rate, down_rate) = self.state.get_traffic_rates(bytes_sent, bytes_received);

        let tcp_str = format!("{}", tcp_count);
        let udp_str = format!("{}", udp_count);
        let up_str = self.state.format_bytes(bytes_sent);
        let down_str = self.state.format_bytes(bytes_received);
        let up_rate_str = self.state.format_rate(up_rate);
        let down_rate_str = self.state.format_rate(down_rate);
        let time_str = self.state.format_time(running_time);
        let cpu_str = format!("{:>5.1}%", cpu_percent);
        let mem_str = self.state.format_bytes(mem_bytes);

        let status = format!(
            " TCP: {:>5} | UDP: {:>5} | UP: {:>8} | DOWN: {:>8} | UPS: {:>9} | DNS: {:>9} | TIME: {:>8} | CPU: {:>6} | MEM: {:>8} ",
            tcp_str,
            udp_str,
            up_str,
            down_str,
            up_rate_str,
            down_rate_str,
            time_str,
            cpu_str,
            mem_str,
        );

        let paragraph = Paragraph::new(status)
            .style(Style::default().bg(Color::Blue).fg(Color::White))
            .alignment(ratatui::layout::Alignment::Center);

        frame.render_widget(paragraph, area);
    }
}

struct CpuSampler {
    last_instant: Instant,
    last_process_100ns: u64,
}

impl CpuSampler {
    fn new() -> Self {
        Self {
            last_instant: Instant::now(),
            last_process_100ns: 0,
        }
    }

    fn sample(&mut self) -> f64 {
        let now = Instant::now();
        let process_time = match get_process_time_100ns() {
            Some(value) => value,
            None => return 0.0,
        };

        if self.last_process_100ns == 0 {
            self.last_process_100ns = process_time;
            self.last_instant = now;
            return 0.0;
        }

        let delta_process = process_time.saturating_sub(self.last_process_100ns);
        let delta_wall = now.duration_since(self.last_instant);
        if delta_wall.is_zero() {
            return 0.0;
        }

        let wall_100ns = (delta_wall.as_nanos() / 100) as u64;
        if wall_100ns == 0 {
            return 0.0;
        }

        let cpu_count = std::thread::available_parallelism()
            .map(|count| count.get() as u64)
            .unwrap_or(1);

        self.last_process_100ns = process_time;
        self.last_instant = now;

        (delta_process as f64 / wall_100ns as f64) * 100.0 / cpu_count as f64
    }
}

fn filetime_to_u64(filetime: FILETIME) -> u64 {
    ((filetime.dwHighDateTime as u64) << 32) | filetime.dwLowDateTime as u64
}

fn get_process_time_100ns() -> Option<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
        .ok()?;
    }
    Some(filetime_to_u64(kernel) + filetime_to_u64(user))
}

fn get_process_memory_bytes() -> Option<u64> {
    let mut counters = PROCESS_MEMORY_COUNTERS::default();
    counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    unsafe {
        GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb)
            .ok()?;
    }
    Some(counters.WorkingSetSize as u64)
}

struct TrafficSample {
    timestamp: Instant,
    bytes_sent: u64,
    bytes_received: u64,
}

struct TrafficSampler {
    window: Duration,
    samples: VecDeque<TrafficSample>,
}

impl TrafficSampler {
    fn new(window: Duration) -> Self {
        Self {
            window,
            samples: VecDeque::new(),
        }
    }

    fn sample(&mut self, bytes_sent: u64, bytes_received: u64) -> (f64, f64) {
        let now = Instant::now();
        self.samples.push_back(TrafficSample {
            timestamp: now,
            bytes_sent,
            bytes_received,
        });

        while let Some(front) = self.samples.front() {
            if now.duration_since(front.timestamp) > self.window {
                self.samples.pop_front();
            } else {
                break;
            }
        }

        if self.samples.len() < 2 {
            return (0.0, 0.0);
        }

        let oldest = self.samples.front().unwrap();
        let newest = self.samples.back().unwrap();
        let span = newest.timestamp.duration_since(oldest.timestamp).as_secs_f64();
        if span <= 0.0 {
            return (0.0, 0.0);
        }

        let up_delta = newest.bytes_sent.saturating_sub(oldest.bytes_sent) as f64;
        let down_delta = newest.bytes_received.saturating_sub(oldest.bytes_received) as f64;
        (up_delta / span, down_delta / span)
    }
}
