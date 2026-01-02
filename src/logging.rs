use chrono::{Local, SecondsFormat};
use log::{LevelFilter, Log, Metadata, Record, SetLoggerError};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

const MAX_LOG_LINES: usize = 50;

struct TuiLogger {
    logs: Arc<Mutex<Vec<String>>>,
    log_file: Mutex<Option<File>>,
}

impl Log for TuiLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let now = format_timestamp();
        let line = format!("[{}] [{:>5}] {}", now, record.level(), record.args());

        let mut logs = self.logs.lock().unwrap();
        logs.push(line.clone());

        if logs.len() > MAX_LOG_LINES {
            logs.remove(0);
        }

        if let Some(ref mut file) = *self.log_file.lock().unwrap() {
            let _ = file.write_all(line.as_bytes());
            let _ = file.write_all(b"\n");
        }
    }

    fn flush(&self) {
        let mut file = self.log_file.lock().unwrap();
        if let Some(ref mut f) = *file {
            let _ = f.flush();
        }
    }
}

static LOGGER: OnceLock<TuiLogger> = OnceLock::new();

fn format_timestamp() -> String {
    Local::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn get_executable_dir() -> Option<PathBuf> {
    let exe_path = std::env::current_exe().ok()?;
    if exe_path.file_name().is_some() {
        Some(exe_path.parent().unwrap_or(&exe_path).to_path_buf())
    } else {
        Some(exe_path)
    }
}

pub fn init(logs: Arc<Mutex<Vec<String>>>) -> Result<(), SetLoggerError> {
    if LOGGER.get().is_some() {
        return Ok(());
    }

    let log_file = if let Some(mut exe_dir) = get_executable_dir() {
        exe_dir.push("proxifyre.log");
        File::options().create(true).append(true).open(exe_dir).ok()
    } else {
        None
    };

    let _ = LOGGER.set(TuiLogger {
        logs,
        log_file: Mutex::new(log_file),
    });
    log::set_logger(LOGGER.get().expect("logger set"))?;
    log::set_max_level(LevelFilter::Info);
    Ok(())
}

pub fn flush() {
    if let Some(logger) = LOGGER.get() {
        logger.flush();
    }
}
