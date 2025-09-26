use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub username: String,
    pub client_ip: IpAddr,
    pub nas_ip: IpAddr,
    pub start_time: SystemTime,
    pub last_activity: SystemTime,
    pub session_timeout: Option<Duration>,
    pub active: bool,
}

impl Session {
    pub fn new(username: String, client_ip: IpAddr, nas_ip: IpAddr) -> Self {
        let now = SystemTime::now();
        Self {
            id: Uuid::new_v4(),
            username,
            client_ip,
            nas_ip,
            start_time: now,
            last_activity: now,
            session_timeout: None,
            active: true,
        }
    }

    pub fn update_activity(&mut self) {
        self.last_activity = SystemTime::now();
    }

    pub fn is_expired(&self) -> bool {
        if let Some(timeout) = self.session_timeout {
            if let Ok(elapsed) = self.start_time.elapsed() {
                return elapsed > timeout;
            }
        }
        false
    }

    pub fn terminate(&mut self) {
        self.active = false;
    }
}