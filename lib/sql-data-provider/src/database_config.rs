use std::time::Duration;

use log::LevelFilter;
use sea_orm::ConnectOptions;
use serde::{Deserialize, Serialize};

/// Optional overrides for SeaORM's connection options. Unset fields retain
/// the defaults of the SeaORM/SQLx versions used by this build.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct DatabasePoolConfig {
    pub max_connections: Option<u32>,
    pub min_connections: Option<u32>,
    /// SeaORM's `connect_timeout` and `acquire_timeout` both configure SQLx's
    /// acquire timeout. Expose only the latter to avoid two settings for one value.
    pub acquire_timeout_seconds: Option<u64>,
    /// Zero disables the idle timeout.
    pub idle_timeout_seconds: Option<u64>,
    /// Zero disables the maximum connection lifetime.
    pub max_lifetime_seconds: Option<u64>,
    pub test_before_acquire: Option<bool>,
    pub test_before_acquire_if_idle_for_seconds: Option<u64>,
    pub connect_lazy: Option<bool>,
    pub sqlx_logging: Option<bool>,
    pub record_stmt_in_spans: Option<bool>,
    pub sqlx_logging_level: Option<String>,
    pub sqlx_slow_statements_logging_level: Option<String>,
    pub sqlx_slow_statements_logging_threshold_millis: Option<u64>,
    /// PostgreSQL only.
    pub statement_timeout_seconds: Option<u64>,
    /// PostgreSQL only.
    pub application_name: Option<String>,
    /// PostgreSQL only.
    pub schema_search_path: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid databasePool configuration: {0}")]
pub struct DatabasePoolConfigError(String);

impl DatabasePoolConfig {
    pub(crate) fn connect_options(
        &self,
        database_url: &str,
    ) -> Result<ConnectOptions, DatabasePoolConfigError> {
        let mut options = ConnectOptions::new(database_url.to_owned());
        if let Some(max) = self.max_connections {
            if max == 0 {
                return Err(DatabasePoolConfigError(
                    "maxConnections must be greater than zero".into(),
                ));
            }
            // In-memory SQLite data lives in connections, and private caches can
            // give separate connections separate databases. Keep SeaORM's
            // single-connection default instead of allowing pool expansion.
            if is_in_memory_sqlite(database_url) {
                return Err(DatabasePoolConfigError(
                    "maxConnections cannot be set for an in-memory SQLite database".into(),
                ));
            }
            options.max_connections(max);
        }
        if let Some(min) = self.min_connections {
            if self.max_connections.is_some_and(|max| min > max) {
                return Err(DatabasePoolConfigError(
                    "minConnections must not exceed maxConnections".into(),
                ));
            }
            options.min_connections(min);
        }
        if let Some(seconds) = self.acquire_timeout_seconds {
            if seconds == 0 {
                return Err(DatabasePoolConfigError(
                    "acquireTimeoutSeconds must be greater than zero".into(),
                ));
            }
            options.acquire_timeout(Duration::from_secs(seconds));
        }
        if let Some(seconds) = self.idle_timeout_seconds {
            options.idle_timeout((seconds > 0).then_some(Duration::from_secs(seconds)));
        }
        if let Some(seconds) = self.max_lifetime_seconds {
            options.max_lifetime((seconds > 0).then_some(Duration::from_secs(seconds)));
        }
        if let Some(value) = self.test_before_acquire {
            options.test_before_acquire(value);
        }
        if let Some(seconds) = self.test_before_acquire_if_idle_for_seconds {
            if self.test_before_acquire == Some(true) {
                return Err(DatabasePoolConfigError(
                    "testBeforeAcquire and testBeforeAcquireIfIdleForSeconds cannot both be set"
                        .into(),
                ));
            }
            options.test_before_acquire_if_idle_for(Duration::from_secs(seconds));
        }
        if let Some(value) = self.connect_lazy {
            options.connect_lazy(value);
        }
        if let Some(value) = self.sqlx_logging {
            options.sqlx_logging(value);
        }
        if let Some(value) = self.record_stmt_in_spans {
            options.record_stmt_in_spans(value);
        }
        if let Some(level) = &self.sqlx_logging_level {
            options.sqlx_logging_level(parse_log_level("sqlxLoggingLevel", level)?);
        }
        if self.sqlx_slow_statements_logging_level.is_some()
            || self.sqlx_slow_statements_logging_threshold_millis.is_some()
        {
            let (default_level, default_threshold) =
                options.get_sqlx_slow_statements_logging_settings();
            let level = self
                .sqlx_slow_statements_logging_level
                .as_deref()
                .map(|value| parse_log_level("sqlxSlowStatementsLoggingLevel", value))
                .transpose()?
                .unwrap_or(default_level);
            let threshold = self
                .sqlx_slow_statements_logging_threshold_millis
                .map(Duration::from_millis)
                .unwrap_or(default_threshold);
            options.sqlx_slow_statements_logging_settings(level, threshold);
        }
        if let Some(seconds) = self.statement_timeout_seconds {
            options.statement_timeout(Duration::from_secs(seconds));
        }
        if let Some(value) = &self.application_name {
            options.set_application_name(value.clone());
        }
        if let Some(value) = &self.schema_search_path {
            options.set_schema_search_path(value.clone());
        }

        Ok(options)
    }
}

fn is_in_memory_sqlite(database_url: &str) -> bool {
    let Some(path_and_query) = database_url
        .strip_prefix("sqlite://")
        .or_else(|| database_url.strip_prefix("sqlite:"))
    else {
        return false;
    };
    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query, ""));
    path == ":memory:"
        || url::form_urlencoded::parse(query.as_bytes())
            .any(|(key, value)| key == "mode" && value == "memory")
}

fn parse_log_level(field: &str, value: &str) -> Result<LevelFilter, DatabasePoolConfigError> {
    value.parse().map_err(|_| {
        DatabasePoolConfigError(format!(
            "{field} must be one of [off, error, warn, info, debug, trace]"
        ))
    })
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn config_uses_camel_case_keys() {
        let config: DatabasePoolConfig = serde_json::from_value(serde_json::json!({
            "maxConnections": 5,
            "acquireTimeoutSeconds": 45,
            "sqlxSlowStatementsLoggingLevel": "warn"
        }))
        .unwrap();
        assert_eq!(config.max_connections, Some(5));
        assert_eq!(config.acquire_timeout_seconds, Some(45));
        assert_eq!(
            config.sqlx_slow_statements_logging_level.as_deref(),
            Some("warn")
        );
    }

    #[test]
    fn unset_options_leave_seaorm_defaults_intact() {
        let options = DatabasePoolConfig::default()
            .connect_options("mysql://localhost/core")
            .unwrap();
        assert_eq!(options.get_max_connections(), None);
        assert_eq!(options.get_acquire_timeout(), None);
        assert_eq!(options.get_idle_timeout(), None);
    }

    #[test]
    fn configured_pool_options_reach_seaorm() {
        let config = DatabasePoolConfig {
            max_connections: Some(5),
            min_connections: Some(2),
            acquire_timeout_seconds: Some(45),
            idle_timeout_seconds: Some(0),
            max_lifetime_seconds: Some(1200),
            test_before_acquire_if_idle_for_seconds: Some(30),
            ..Default::default()
        };
        let options = config.connect_options("mysql://localhost/core").unwrap();
        assert_eq!(options.get_max_connections(), Some(5));
        assert_eq!(options.get_min_connections(), Some(2));
        assert_eq!(options.get_acquire_timeout(), Some(Duration::from_secs(45)));
        assert_eq!(options.get_idle_timeout(), Some(None));
        assert_eq!(
            options.get_max_lifetime(),
            Some(Some(Duration::from_secs(1200)))
        );
        assert!(!options.get_test_before_acquire());
        assert_eq!(
            options.get_test_before_acquire_if_idle_for(),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn in_memory_sqlite_rejects_an_explicit_pool_limit() {
        let options = DatabasePoolConfig::default()
            .connect_options("sqlite::memory:")
            .unwrap();
        assert_eq!(options.get_max_connections(), None);

        let config = DatabasePoolConfig {
            max_connections: Some(1),
            ..Default::default()
        };
        for database_url in [
            "sqlite::memory:",
            "sqlite://:memory:",
            "sqlite://?mode=memory",
            "sqlite://file:core?mode=memory&cache=shared",
        ] {
            let error = config.connect_options(database_url).unwrap_err();
            assert!(error.to_string().contains("in-memory SQLite"));
        }
    }

    #[test]
    fn file_backed_sqlite_allows_a_larger_pool() {
        let config = DatabasePoolConfig {
            max_connections: Some(5),
            ..Default::default()
        };
        let options = config.connect_options("sqlite://core.db?mode=rwc").unwrap();
        assert_eq!(options.get_max_connections(), Some(5));
    }

    #[test]
    fn rejects_invalid_limits_and_ping_settings() {
        let config = DatabasePoolConfig {
            max_connections: Some(2),
            min_connections: Some(3),
            ..Default::default()
        };
        assert!(config.connect_options("mysql://localhost/core").is_err());

        let config = DatabasePoolConfig {
            test_before_acquire: Some(true),
            test_before_acquire_if_idle_for_seconds: Some(30),
            ..Default::default()
        };
        assert!(config.connect_options("mysql://localhost/core").is_err());
    }
}
