use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use core_server::ServerConfig;
use core_server::init::initialize_core;
use core_server::router::start_server;
use one_core::config::core_config::AppConfig;

use crate::fixtures;

/// Every template in `config/examples` must be sufficient on its own to start
/// the core server: no additional config overlays, no external infrastructure.
///
/// The templates are loaded the same way `core-server --config <file>` loads
/// them, i.e. on top of the `config/config.yml` stub.
#[tokio::test]
async fn test_server_starts_from_example_configs() {
    let root = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set by cargo/nextest");
    let examples_dir = PathBuf::from(format!("{root}/../../config/examples"));

    let mut examples: Vec<PathBuf> = std::fs::read_dir(&examples_dir)
        .expect("Failed to read examples directory")
        .map(|entry| entry.expect("Failed to read directory entry").path())
        .filter(|path| path.is_file())
        .collect();
    examples.sort();

    assert!(
        !examples.is_empty(),
        "No example configs found in {}",
        examples_dir.display()
    );

    let mut failures = vec![];
    for example in examples {
        if let Err(err) = start_server_from_example(&root, &example).await {
            let name = example.file_name().unwrap_or(example.as_os_str());
            failures.push(format!("{}: {err}", name.to_string_lossy()));
        }
    }

    assert!(
        failures.is_empty(),
        "Example configs failed to start the server:\n{}",
        failures.join("\n")
    );
}

async fn start_server_from_example(root: &str, example: &Path) -> Result<(), String> {
    let app_config: AppConfig<ServerConfig> = AppConfig::from_files(&[
        Path::new(&format!("{root}/../../config/config.yml")),
        example,
    ])
    .map_err(|err| format!("failed parsing config: {err}"))?;

    // The database is the one piece of infrastructure the server needs at boot.
    // `create_db` provides an in-memory SQLite unless the test run is
    // configured to use a database cluster.
    let db_conn = fixtures::create_db(&app_config).await;

    let core = initialize_core(&app_config, db_conn)
        .await
        .map_err(|err| format!("failed initializing core: {err}"))?;

    let listener = TcpListener::bind("127.0.0.1:0").map_err(|err| err.to_string())?;
    let base_url = format!(
        "http://{}",
        listener.local_addr().map_err(|err| err.to_string())?
    );
    let handle = tokio::spawn(async move { start_server(listener, app_config.app, core).await });

    let result = wait_until_healthy(&base_url).await;
    handle.abort();
    result
}

/// The `/health` endpoint is only routed when `enableServerInfo` is set, so
/// example templates are expected to enable it.
async fn wait_until_healthy(base_url: &str) -> Result<(), String> {
    let url = format!("{base_url}/health");
    let mut last_error = None;

    for _ in 0..50 {
        match reqwest::get(&url).await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => {
                last_error = Some(format!(
                    "unexpected status {} (is `app.enableServerInfo` set?)",
                    response.status()
                ))
            }
            Err(err) => last_error = Some(err.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(format!(
        "health check on {url} failed: {}",
        last_error.unwrap_or_default()
    ))
}
