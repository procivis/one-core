use super::dto::ConfigRestDTO;
use one_core::service::config::dto::ConfigDTO;

impl From<ConfigDTO> for ConfigRestDTO {
    fn from(config: ConfigDTO) -> Self {
        Self {
            format: config.format,
            exchange: config.exchange,
            transport: config.transport,
            revocation: config.revocation,
            did: config.did,
            datatype: config.datatype,
        }
    }
}
