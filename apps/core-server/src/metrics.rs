use std::sync::OnceLock;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use prometheus::{HistogramOpts, HistogramVec, IntCounter, Registry};

// creates the custom registry and registers the custom metrics
pub fn setup() {
    let registry = registry();
    registry
        .register(Box::new(incoming_requests_counter().clone()))
        .expect("Failed registering counter");

    registry
        .register(Box::new(response_time_hist().clone()))
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

fn response_time_hist() -> &'static HistogramVec {
    static RESPONSE_TIME_COLLECTOR: OnceLock<HistogramVec> = OnceLock::new();

    RESPONSE_TIME_COLLECTOR.get_or_init(|| {
        HistogramVec::new(
            HistogramOpts::new("response_time", "Response Times"),
            &["env"],
        )
        .expect("failed to create metric")
    })
}

pub(crate) fn track_request_count_and_time(response_time: f64) {
    incoming_requests_counter().inc();

    response_time_hist()
        .with_label_values(&["dev"])
        .observe(response_time);
}

pub(crate) async fn get_metrics() -> Response {
    match encode_metrics() {
        Ok(result) => (StatusCode::OK, result).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Metrics encoding error: {:?}", error),
        )
            .into_response(),
    }
}

fn encode_metrics() -> Result<String, prometheus::Error> {
    let encoder = prometheus::TextEncoder::new();
    let mut metrics = String::new();

    encoder.encode_utf8(&registry().gather(), &mut metrics)?;
    encoder.encode_utf8(&prometheus::gather(), &mut metrics)?;

    Ok(metrics)
}
