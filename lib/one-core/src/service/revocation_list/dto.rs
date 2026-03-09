use crate::config::core_config::RevocationType;
use crate::model::revocation_list::StatusListCredentialFormat;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationListResponseDTO {
    pub revocation_list: String,
    pub format: StatusListCredentialFormat,
    pub r#type: RevocationType,
}
