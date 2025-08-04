use std::{env, time::Duration};

pub fn pcs_log_inv_rate() -> usize {
    env::var("PCS_LOG_INV_RATE")
        .ok()
        .and_then(|r| r.parse().ok())
        .unwrap_or(1)
}

pub fn po2(exps: impl IntoIterator<Item = usize>) -> impl Iterator<Item = usize> {
    exps.into_iter().map(|exp| 1 << exp)
}

pub fn human_time(time: Duration) -> String {
    let time = time.as_nanos();
    if time < 1_000 {
        format!("{time} ns")
    } else if time < 1_000_000 {
        format!("{:.2} µs", time as f64 / 1_000.0)
    } else if time < 1_000_000_000 {
        format!("{:.2} ms", time as f64 / 1_000_000.0)
    } else {
        format!("{:.2} s", time as f64 / 1_000_000_000.0)
    }
}

pub fn human_size(size: f64) -> String {
    if size < 1000.0 {
        format!("{size:.2} B")
    } else if size < 1000.0 * 2f64.powi(10) {
        format!("{:.2} KB", size / 2f64.powi(10))
    } else {
        format!("{:.2} MB", size / 2f64.powi(20))
    }
}

pub fn human_throughput(throughput: f64) -> String {
    if throughput < 1_000.0 {
        format!("{throughput:.2} /s")
    } else if throughput < 1_000_000.0 {
        format!("{:.2} K/s", throughput / 1_000.0)
    } else {
        format!("{:.2} M/s", throughput / 1_000_000.0)
    }
}
