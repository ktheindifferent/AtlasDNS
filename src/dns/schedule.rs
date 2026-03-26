//! Scheduled DNS blocking (parental controls).
//!
//! [`ScheduleStore`] evaluates active schedules on every DNS query to decide
//! whether a given `(client_ip, domain)` pair should be blocked based on the
//! current time-of-day and day-of-week.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Broad content category for schedule-based blocking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BlockCategory {
    Social,
    Gaming,
    Streaming,
    Adult,
    All,
}

/// Action to enforce during a schedule window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "category")]
pub enum ScheduleAction {
    /// Block all DNS queries.
    BlockAll,
    /// Block only queries matching the specified category.
    BlockCategory(BlockCategory),
}

/// A timed blocking schedule for a client IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSchedule {
    /// Unique schedule ID.
    pub id: String,
    /// Client IP this schedule applies to (or "all" for every client).
    pub client_ip: String,
    /// Days of week (0=Sunday … 6=Saturday).
    pub days_of_week: Vec<u8>,
    /// Start time as "HH:MM" (24-hour).
    pub start_time: String,
    /// End time as "HH:MM" (24-hour).
    pub end_time: String,
    /// What to block during the window.
    pub action: ScheduleAction,
    /// Unix timestamp of creation.
    pub created_at: u64,
}

/// Well-known domains per category used for category-based blocking.
fn category_domains(cat: &BlockCategory) -> &'static [&'static str] {
    match cat {
        BlockCategory::Social => &[
            "facebook.com", "twitter.com", "instagram.com", "tiktok.com",
            "snapchat.com", "reddit.com", "pinterest.com", "linkedin.com",
            "tumblr.com", "discord.com",
        ],
        BlockCategory::Gaming => &[
            "steampowered.com", "epicgames.com", "roblox.com", "minecraft.net",
            "battlenet.com", "ea.com", "ubisoft.com", "twitch.tv",
        ],
        BlockCategory::Streaming => &[
            "netflix.com", "youtube.com", "hulu.com", "disneyplus.com",
            "primevideo.com", "hbomax.com", "peacocktv.com", "paramountplus.com",
            "crunchyroll.com", "spotify.com",
        ],
        BlockCategory::Adult => &[
            "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com",
            "redtube.com", "youporn.com", "tube8.com", "brazzers.com",
        ],
        BlockCategory::All => &[],
    }
}

/// Parse "HH:MM" → (hours, minutes). Returns None on parse failure.
fn parse_hhmm(s: &str) -> Option<(u8, u8)> {
    let mut parts = s.splitn(2, ':');
    let h: u8 = parts.next()?.parse().ok()?;
    let m: u8 = parts.next()?.parse().ok()?;
    if h > 23 || m > 59 { return None; }
    Some((h, m))
}

impl TimeSchedule {
    /// Returns true if the schedule is active right now.
    pub fn is_active_now(&self) -> bool {
        // Use unix timestamp to derive day-of-week and time-of-day (UTC).
        let secs = now_secs();
        // Days since epoch (1970-01-01 was a Thursday = day 4)
        let days = secs / 86400;
        let dow = ((days + 4) % 7) as u8; // 0=Sun

        if !self.days_of_week.contains(&dow) {
            return false;
        }

        let time_of_day = secs % 86400;
        let hour = (time_of_day / 3600) as u8;
        let minute = ((time_of_day % 3600) / 60) as u8;
        let current_mins = hour as u16 * 60 + minute as u16;

        let (sh, sm) = parse_hhmm(&self.start_time).unwrap_or((0, 0));
        let (eh, em) = parse_hhmm(&self.end_time).unwrap_or((23, 59));
        let start_mins = sh as u16 * 60 + sm as u16;
        let end_mins = eh as u16 * 60 + em as u16;

        current_mins >= start_mins && current_mins < end_mins
    }

    /// Returns true if `domain` is blocked by this schedule's action.
    pub fn blocks_domain(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        match &self.action {
            ScheduleAction::BlockAll => true,
            ScheduleAction::BlockCategory(cat) => {
                if matches!(cat, BlockCategory::All) {
                    return true;
                }
                let known = category_domains(cat);
                known.iter().any(|&d| domain == d || domain.ends_with(&format!(".{}", d)))
            }
        }
    }
}

/// Thread-safe store for time-based blocking schedules.
pub struct ScheduleStore {
    schedules: RwLock<Vec<TimeSchedule>>,
}

impl ScheduleStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { schedules: RwLock::new(Vec::new()) })
    }

    /// Add a schedule, generating an ID if empty.
    pub fn add_schedule(&self, mut sched: TimeSchedule) {
        if sched.id.is_empty() {
            sched.id = uuid::Uuid::new_v4().to_string();
        }
        if sched.created_at == 0 {
            sched.created_at = now_secs();
        }
        self.schedules.write().push(sched);
    }

    /// Return all schedules.
    pub fn get_schedules(&self) -> Vec<TimeSchedule> {
        self.schedules.read().clone()
    }

    /// Delete a schedule by ID. Returns true if found and removed.
    pub fn delete_schedule(&self, id: &str) -> bool {
        let mut list = self.schedules.write();
        let before = list.len();
        list.retain(|s| s.id != id);
        list.len() < before
    }

    /// Returns true if `(client_ip, domain)` is currently blocked by any active schedule.
    pub fn is_blocked(&self, client_ip: &str, domain: &str) -> bool {
        let list = self.schedules.read();
        list.iter().any(|s| {
            (s.client_ip == client_ip || s.client_ip == "all")
                && s.is_active_now()
                && s.blocks_domain(domain)
        })
    }

    /// Bulk-load from persistent storage at startup.
    pub fn load_from_storage(&self, schedules: Vec<TimeSchedule>) {
        *self.schedules.write() = schedules;
    }
}

