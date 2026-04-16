use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use chrono::Local;
use tracing::{info, warn};

/// Session logger that writes authentication events to a file.
pub struct SessionLogger {
    file: Mutex<File>,
    path: String,
}

impl SessionLogger {
    /// Create a new session logger that writes to the specified file.
    pub fn new(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        info!(path = %path, "Session log file opened");

        Ok(Self {
            file: Mutex::new(file),
            path: path.to_string(),
        })
    }

    /// Log an authentication event.
    pub fn log_auth(
        &self,
        username: &str,
        calling_station_id: Option<&str>,
        called_station_id: Option<&str>,
        result: &str,
        filter_id: Option<&str>,
    ) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let calling = calling_station_id.unwrap_or("-");
        let called = called_station_id.unwrap_or("-");
        let filter = filter_id.unwrap_or("-");

        let line = format!(
            "{} | {} | {} | {} | {} | {}\n",
            timestamp, username, calling, called, result, filter
        );

        match self.file.lock() {
            Ok(mut file) => {
                if let Err(e) = file.write_all(line.as_bytes()) {
                    warn!(error = %e, "Failed to write to session log");
                }
                // Flush to ensure immediate write
                let _ = file.flush();
            }
            Err(e) => {
                warn!(error = %e, "Failed to lock session log file");
            }
        }
    }

    /// Write header line if file is empty.
    pub fn write_header_if_empty(&self) {
        if let Ok(metadata) = std::fs::metadata(&self.path) {
            if metadata.len() == 0 {
                let header = "# Timestamp | Username | Calling-Station-Id | Called-Station-Id | Result | Filter-Id\n";
                if let Ok(mut file) = self.file.lock() {
                    let _ = file.write_all(header.as_bytes());
                    let _ = file.flush();
                }
            }
        }
    }

    /// Get the log file path.
    pub fn path(&self) -> &str {
        &self.path
    }
}
