use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub enum LimitCategory {
    Create,
    Claim,
    Manage,
}

impl LimitCategory {
    fn settings(self) -> (u32, Duration) {
        match self {
            LimitCategory::Create => (20, Duration::from_secs(60)),
            LimitCategory::Claim => (60, Duration::from_secs(60)),
            LimitCategory::Manage => (30, Duration::from_secs(60)),
        }
    }
}

#[derive(Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<String, Window>>,
}

struct Window {
    started_at: Instant,
    count: u32,
}

impl RateLimiter {
    pub fn allow(&self, category: LimitCategory, ip: &str) -> bool {
        let (limit, window) = category.settings();
        let key = format!("{:?}:{ip}", category as u8);
        let mut guard = self.windows.lock().expect("rate limiter lock");
        let entry = guard.entry(key).or_insert(Window {
            started_at: Instant::now(),
            count: 0,
        });

        if entry.started_at.elapsed() >= window {
            entry.started_at = Instant::now();
            entry.count = 0;
        }

        if entry.count >= limit {
            return false;
        }

        entry.count += 1;
        true
    }
}
