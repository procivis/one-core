use std::sync::OnceLock;

use prometheus::{CounterVec, HistogramOpts, HistogramVec, IntCounter, Opts, Registry};

// creates the custom registry and registers the custom metrics
pub fn setup() {
    let registry = registry();
    registry
        .register(Box::new(incoming_requests_counter().clone()))
        .expect("Failed registering counter");

    registry
        .register(Box::new(response_time_hist().clone()))
        .expect("Failed registering counter");

    registry
        .register(Box::new(response_status_counter().clone()))
        .expect("Failed registering counter");
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();

    REGISTRY.get_or_init(Registry::new)
}

fn incoming_requests_counter() -> &'static IntCounter {
    static INCOMING_REQUESTS: OnceLock<IntCounter> = OnceLock::new();

    INCOMING_REQUESTS.get_or_init(|| {
        IntCounter::new("incoming_requests", "Incoming Requests").expect("failed to create metric")
    })
}

fn response_status_counter() -> &'static CounterVec {
    static INCOMING_REQUESTS_COUNTER: OnceLock<CounterVec> = OnceLock::new();

    INCOMING_REQUESTS_COUNTER.get_or_init(|| {
        CounterVec::new(
            Opts::new("status_response", "Number of responses"),
            &["method", "path", "status"],
        )
        .expect("Failed registering counter")
    })
}

fn response_time_hist() -> &'static HistogramVec {
    static RESPONSE_TIME_COLLECTOR: OnceLock<HistogramVec> = OnceLock::new();

    RESPONSE_TIME_COLLECTOR.get_or_init(|| {
        HistogramVec::new(
            HistogramOpts::new("response_time", "Response Times"),
            &["method", "path", "status"],
        )
        .expect("failed to create metric")
    })
}

pub(crate) fn track_response_status_code(method: &str, path: &str, status: &str, duration: f64) {
    let labels = vec![method, path, status];

    incoming_requests_counter().inc();

    response_status_counter()
        .with_label_values(labels.as_slice())
        .inc();

    response_time_hist()
        .with_label_values(labels.as_slice())
        .observe(duration);
}

pub(crate) fn encode_metrics() -> Result<String, prometheus::Error> {
    let encoder = prometheus::TextEncoder::new();
    let mut metrics = String::new();

    encoder.encode_utf8(&registry().gather(), &mut metrics)?;
    encoder.encode_utf8(&prometheus::gather(), &mut metrics)?;

    Ok(metrics)
}
