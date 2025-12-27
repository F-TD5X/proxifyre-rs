use chrono::{Local, SecondsFormat};
use log::{LevelFilter, Log, Metadata, Record, SetLoggerError};
use std::sync::{Arc, Mutex, OnceLock};

const MAX_LOG_LINES: usize = 1000;

struct TuiLogger {
    logs: Arc<Mutex<Vec<String>>>,
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
        logs.push(line);
        if logs.len() > MAX_LOG_LINES {
            let overflow = logs.len() - MAX_LOG_LINES;
            logs.drain(0..overflow);
        }
    }

    fn flush(&self) {}
}

static LOGGER: OnceLock<TuiLogger> = OnceLock::new();

fn format_timestamp() -> String {
    Local::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn init(logs: Arc<Mutex<Vec<String>>>) -> Result<(), SetLoggerError> {
    if LOGGER.get().is_some() {
        return Ok(());
    }

    let _ = LOGGER.set(TuiLogger { logs });
    log::set_logger(LOGGER.get().expect("logger set"))?;
    log::set_max_level(LevelFilter::Info);
    Ok(())
}
