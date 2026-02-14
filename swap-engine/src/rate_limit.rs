use crate::types::AppError;
use std::collections::HashMap;
use std::net::IpAddr;

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_ms: u128,
    cap: f64,
    refill_per_ms: f64,
}

impl TokenBucket {
    fn new(per_min: u64, now_ms: u128) -> Self {
        let cap = per_min.max(1) as f64;
        Self {
            tokens: cap,
            last_ms: now_ms,
            cap,
            refill_per_ms: cap / 60_000.0,
        }
    }

    fn try_take(&mut self, now_ms: u128, n: f64) -> bool {
        let dt = now_ms.saturating_sub(self.last_ms) as f64;
        if dt > 0.0 {
            self.tokens = (self.tokens + dt * self.refill_per_ms).min(self.cap);
            self.last_ms = now_ms;
        }
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

struct RateLimiterEntry {
    bucket: TokenBucket,
    last_seen_ms: u128,
}

pub struct RateLimiter {
    ok_per_min: u64,
    bad_per_min: u64,
    max_entries: usize,
    idle_evict_ms: u128,
    ok: HashMap<IpAddr, RateLimiterEntry>,
    bad: HashMap<IpAddr, RateLimiterEntry>,
}

impl RateLimiter {
    pub fn from_env() -> Self {
        let ok_per_min = env_u64("SWAP_ENGINE_RL_OK_PER_MIN", 60);
        let bad_per_min = env_u64("SWAP_ENGINE_RL_BAD_PER_MIN", 10);
        let max_entries = env_u64("SWAP_ENGINE_RL_MAX_ENTRIES", 20_000) as usize;
        let idle_evict_ms = (env_u64("SWAP_ENGINE_RL_IDLE_EVICT_SECS", 600) as u128) * 1000;
        Self {
            ok_per_min,
            bad_per_min,
            max_entries,
            idle_evict_ms,
            ok: HashMap::new(),
            bad: HashMap::new(),
        }
    }

    fn cleanup(&mut self, now_ms: u128) {
        if self.ok.len() + self.bad.len() <= self.max_entries {
            return;
        }
        let cutoff = now_ms.saturating_sub(self.idle_evict_ms);
        self.ok.retain(|_, e| e.last_seen_ms >= cutoff);
        self.bad.retain(|_, e| e.last_seen_ms >= cutoff);
        // Hard cap: evict oldest entries (do NOT clear all; that resets limits and enables bypass).
        let total = self.ok.len() + self.bad.len();
        if total <= self.max_entries {
            return;
        }
        // Remove oldest entries until within cap.
        let mut all: Vec<(u128, bool, IpAddr)> = Vec::with_capacity(total);
        for (ip, e) in self.ok.iter() {
            all.push((e.last_seen_ms, true, *ip)); // true => ok map
        }
        for (ip, e) in self.bad.iter() {
            all.push((e.last_seen_ms, false, *ip)); // false => bad map
        }
        all.sort_by_key(|(ts, _, _)| *ts);
        let to_remove = all.len().saturating_sub(self.max_entries);
        for (_, is_ok, ip) in all.into_iter().take(to_remove) {
            if is_ok {
                self.ok.remove(&ip);
            } else {
                self.bad.remove(&ip);
            }
        }
    }

    pub fn allow_ok(&mut self, ip: IpAddr, now_ms: u128) -> bool {
        self.cleanup(now_ms);
        let ent = self.ok.entry(ip).or_insert_with(|| RateLimiterEntry {
            bucket: TokenBucket::new(self.ok_per_min, now_ms),
            last_seen_ms: now_ms,
        });
        ent.last_seen_ms = now_ms;
        ent.bucket.try_take(now_ms, 1.0)
    }

    pub fn allow_bad(&mut self, ip: IpAddr, now_ms: u128) -> bool {
        self.cleanup(now_ms);
        let ent = self.bad.entry(ip).or_insert_with(|| RateLimiterEntry {
            bucket: TokenBucket::new(self.bad_per_min, now_ms),
            last_seen_ms: now_ms,
        });
        ent.last_seen_ms = now_ms;
        ent.bucket.try_take(now_ms, 1.0)
    }
}

pub async fn rate_limit_ok(st: &crate::state::AppState, ip: IpAddr) -> Result<(), AppError> {
    let now = crate::utils::now_ms();
    let mut rl = st.rate_limiter.lock().await;
    if !rl.allow_ok(ip, now) {
        return Err(AppError::TooManyRequests("rate limit exceeded".into()));
    }
    Ok(())
}

pub async fn rate_limit_bad(st: &crate::state::AppState, ip: IpAddr) -> Result<(), AppError> {
    let now = crate::utils::now_ms();
    let mut rl = st.rate_limiter.lock().await;
    if !rl.allow_bad(ip, now) {
        return Err(AppError::TooManyRequests("too many bad requests".into()));
    }
    Ok(())
}

