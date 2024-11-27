pub fn human_size(size: f64) -> String {
    if size < 1000.0 {
        format!("{size:.2}")
    } else if size < 1000.0 * 2f64.powi(10) {
        format!("{:.2}KB", size / 2f64.powi(10))
    } else {
        format!("{:.2}MB", size / 2f64.powi(20))
    }
}

pub fn human_throughput(throughput: f64) -> String {
    if throughput < 1_000.0 {
        format!("{throughput:.2}")
    } else if throughput < 1_000_000.0 {
        format!("{:.2}K", throughput / 1_000.0)
    } else {
        format!("{:.2}M", throughput / 1_000_000.0)
    }
}
