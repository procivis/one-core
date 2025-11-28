use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;

use clap::Parser;
use core_server::init::{initialize_core, initialize_sentry, initialize_tracing};
use core_server::router::start_server;
use core_server::{ServerConfig, metrics};
use one_core::OneCore;
use one_core::config::core_config::AppConfig;
use one_core::service::error::ServiceError;
use secrecy::SecretString;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "FILE")]
    config: Option<Vec<PathBuf>>,

    /// Skip DB migration on startup
    #[arg(long, action)]
    skip_migration: bool,

    /// Specific task to run
    #[arg(long)]
    task: Option<String>,

    /// Decrypt and load a database from a backup file.
    /// This will override the databaseUrl specified in the config file.
    #[arg(long)]
    backup_from: Option<PathBuf>,

    /// Backup decryption passphrase.
    #[arg(long)]
    backup_secret: Option<SecretString>,

    /// Target filename under which the decrypted backup database should be
    /// saved. If not specified, a random name inside the system's temporary
    /// directory will be used. Note that the file will *NOT* be deleted
    /// upon program exit.
    #[arg(long)]
    backup_to: Option<PathBuf>,
}

#[expect(clippy::expect_used)]
#[expect(clippy::panic)]
fn main() {
    let cli = Cli::parse();

    let mut config_files = cli.config.unwrap_or_default();
    config_files.insert(0, "config/config.yml".into());

    let app_config = {
        let mut config: AppConfig<ServerConfig> =
            AppConfig::from_files(&config_files).expect("Failed creating config");

        match load_backup(cli.backup_from, cli.backup_secret, cli.backup_to) {
            // Calling .display() here performs a lossy conversion, which is quite bad,
            // but it's either that, or making cli.backup_to a string.
            Ok(Some(backup_path)) => {
                config.app.database_url = format!("sqlite://{}", backup_path.display())
            }
            Ok(None) => { /* Do nothing */ }
            Err(e) => panic!("Failed to load backup: {}", e),
        }

        config
    };

    // SAFETY: at that stage, it's a single-threaded application
    unsafe { env::set_var("MIGRATION_CORE_URL", &app_config.app.core_base_url) };

    let _sentry_init_guard = initialize_sentry(&app_config.app);

    initialize_tracing(&app_config.app);
    metrics::setup();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Unable to create tokio runtime")
        .block_on(async {
            let db_conn =
                sql_data_provider::db_conn(&app_config.app.database_url, !cli.skip_migration)
                    .await
                    .expect("Unable to establish database connection");

            let core = initialize_core(&app_config, db_conn)
                .await
                .expect("Unable to initialize core");

            if let Some(task) = cli.task {
                run_task(task, core).await
            } else {
                run_server(app_config.app, core).await
            }
        })
}

#[expect(clippy::expect_used)]
async fn run_server(config: ServerConfig, core: OneCore) {
    let addr = SocketAddr::new(
        config
            .server_ip
            .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
        config.server_port.unwrap_or(3000),
    );

    let listener = TcpListener::bind(addr).expect("Failed to bind to address");

    start_server(listener, config, core).await
}

#[expect(clippy::expect_used)]
async fn run_task(task: String, core: OneCore) {
    match core.task_service.run(&task).await {
        Ok(result) => {
            print!(
                "{}",
                serde_json::to_string_pretty(&result).expect("Failed to format JSON")
            );
        }
        Err(err) => {
            #[allow(clippy::print_stderr)]
            {
                eprint!("{err}");
            }
            std::process::exit(1)
        }
    }
}

fn load_backup(
    in_path: Option<PathBuf>,
    secret: Option<SecretString>,
    out_path: Option<PathBuf>,
) -> Result<Option<PathBuf>, ServiceError> {
    let in_path = match in_path {
        Some(value) => value,
        None => return Ok(None),
    };

    let out_path = out_path.unwrap_or_else(|| {
        let mut tmpnam = env::temp_dir();
        tmpnam.push(format!(
            "core-server-{}.sqlite",
            time::OffsetDateTime::now_utc().unix_timestamp()
        ));
        tmpnam
    });

    let _metadata = one_core::service::backup::BackupService::unpack_backup(
        secret.unwrap_or_default(),
        in_path,
        out_path.clone(),
    )?;
    Ok(Some(out_path))
}
