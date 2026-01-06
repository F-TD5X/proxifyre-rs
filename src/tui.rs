use crate::router::SocksLocalRouter;
use crate::windows::stats::{StatsSnapshot, SystemStats};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, List, ListItem, Paragraph},
};
use std::collections::VecDeque;
use std::io::stdout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task;

pub struct TuiState {
    pub logs: Arc<Mutex<Vec<String>>>,
    pub router: Arc<SocksLocalRouter>,
    shutdown: AtomicBool,
    traffic_sampler: Mutex<TrafficSampler>,
    stats: Arc<dyn SystemStats>,
    last_stats: AsyncMutex<StatsSnapshot>,
}

impl TuiState {
    pub fn new(
        router: Arc<SocksLocalRouter>,
        logs: Arc<Mutex<Vec<String>>>,
        stats: Arc<dyn SystemStats>,
    ) -> Self {
        Self {
            logs,
            router,
            shutdown: AtomicBool::new(false),
            traffic_sampler: Mutex::new(TrafficSampler::new(Duration::from_secs(5))),
            stats,
            last_stats: AsyncMutex::new(StatsSnapshot::default()),
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

    pub async fn refresh_stats(&self) {
        let snapshot = self.stats.sample().await;
        *self.last_stats.lock().await = snapshot;
    }

    pub async fn get_process_usage(&self) -> (f64, u64) {
        let snapshot = *self.last_stats.lock().await;
        (snapshot.cpu_percent, snapshot.mem_bytes)
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

    pub fn start_stats_task(self: &Arc<Self>) -> task::JoinHandle<()> {
        let state = Arc::clone(self);
        task::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            loop {
                interval.tick().await;
                if state.should_shutdown() {
                    break;
                }
                state.refresh_stats().await;
            }
        })
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
        execute!(stdout(), EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout());
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

        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        disable_raw_mode()?;
        terminal.show_cursor()?;
        Ok(())
    }

    fn draw(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
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

        let stats = self.state.last_stats.blocking_lock();
        let cpu_percent = stats.cpu_percent;
        let mem_bytes = stats.mem_bytes;

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
        let span = newest
            .timestamp
            .duration_since(oldest.timestamp)
            .as_secs_f64();
        if span <= 0.0 {
            return (0.0, 0.0);
        }

        let up_delta = newest.bytes_sent.saturating_sub(oldest.bytes_sent) as f64;
        let down_delta = newest.bytes_received.saturating_sub(oldest.bytes_received) as f64;
        (up_delta / span, down_delta / span)
    }
}
