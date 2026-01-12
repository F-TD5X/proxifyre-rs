use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::task;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

#[derive(Clone, Copy, Debug, Default)]
pub struct StatsSnapshot {
    pub cpu_percent: f64,
    pub mem_bytes: u64,
}

#[async_trait::async_trait]
pub trait SystemStats: Send + Sync {
    async fn sample(&self) -> StatsSnapshot;
}

#[derive(Clone, Default)]
pub struct WindowsSystemStats {
    cpu_sampler: Arc<Mutex<CpuSampler>>,
}

impl WindowsSystemStats {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl SystemStats for WindowsSystemStats {
    async fn sample(&self) -> StatsSnapshot {
        let sampler = Arc::clone(&self.cpu_sampler);
        task::spawn_blocking(move || {
            let mut sampler = sampler.lock().unwrap();
            let cpu = sampler.sample().clamp(0.0, 100.0);
            let mem = get_process_memory_bytes().unwrap_or(0);
            StatsSnapshot {
                cpu_percent: cpu,
                mem_bytes: mem,
            }
        })
        .await
        .unwrap_or_default()
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

impl Default for CpuSampler {
    fn default() -> Self {
        Self::new()
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
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    unsafe {
        GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb).ok()?;
    }
    Some(counters.WorkingSetSize as u64)
}
