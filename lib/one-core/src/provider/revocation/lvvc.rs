use serde::Deserialize;
use shared_types::DidValue;

use crate::{
    model::credential::Credential,
    provider::{credential_formatter::model::CredentialStatus, revocation::RevocationMethod},
    service::error::ServiceError,
};

use super::CredentialRevocationInfo;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub credential_expiry: u64,
}

pub struct Lvvc {
    _params: Params,
}

#[async_trait::async_trait]
impl RevocationMethod for Lvvc {
    fn get_status_type(&self) -> String {
        "LVVC".to_string()
    }

    async fn add_issued_credential(
        &self,
        _credential: &Credential,
    ) -> Result<Option<CredentialRevocationInfo>, ServiceError> {
        unimplemented!()
    }

    async fn mark_credential_revoked(&self, _credential: &Credential) -> Result<(), ServiceError> {
        unimplemented!()
    }

    async fn check_credential_revocation_status(
        &self,
        _credential_status: &CredentialStatus,
        _issuer_did: &DidValue,
    ) -> Result<bool, ServiceError> {
        unimplemented!()
    }
}

impl Lvvc {
    pub fn new(params: Params) -> Self {
        Self { _params: params }
    }
}
