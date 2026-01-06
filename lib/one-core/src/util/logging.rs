use std::fmt::Display;

/// Returns the quoted provider name (using backticks) or "-" if provider is `None`.
pub fn quoted_opt_provider(provider: &Option<impl Display>) -> String {
    provider
        .as_ref()
        .map(|p| format!("`{p}`"))
        .unwrap_or_else(|| "-".to_string())
}
