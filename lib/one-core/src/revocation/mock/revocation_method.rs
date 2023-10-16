use crate::{
    model::credential::Credential, revocation::CredentialRevocationInfo,
    service::error::ServiceError,
};
use mockall::*;

#[derive(Default)]
struct RevocationMethod;

mock! {
    pub RevocationMethod {
        pub fn add_issued_credential(
            &self,
            credential: &Credential,
        ) -> Result<Option<CredentialRevocationInfo>, ServiceError>;

        pub fn mark_credential_revoked(&self, credential: &Credential) -> Result<(), ServiceError>;
    }
}

#[async_trait::async_trait]
impl crate::revocation::RevocationMethod for MockRevocationMethod {
    async fn add_issued_credential(
        &self,
        credential: &Credential,
    ) -> Result<Option<CredentialRevocationInfo>, ServiceError> {
        self.add_issued_credential(credential)
    }

    async fn mark_credential_revoked(&self, credential: &Credential) -> Result<(), ServiceError> {
        self.mark_credential_revoked(credential)
    }
}
