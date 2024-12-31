use binius_utils::tracing::init_tracing;

pub mod hash;

pub fn setup_trace() {
    init_tracing().unwrap();
}
