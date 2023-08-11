pub mod config_mapper;

use one_core::config::data_structure::{ConfigKind, UnparsedConfig};

pub fn load_config(path: &std::path::Path) -> Result<UnparsedConfig, std::io::Error> {
    let content = std::fs::read_to_string(path)?;

    let kind = match path.extension() {
        None => ConfigKind::Yaml,
        Some(value) => match value.to_str() {
            Some("json") => ConfigKind::Json,
            _ => ConfigKind::Yaml,
        },
    };

    Ok(UnparsedConfig { content, kind })
}
