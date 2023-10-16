use std::collections::HashMap;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::bitstring::generate_bitstring;
use crate::credential_formatter::CredentialStatus;
use crate::model::credential::{
    Credential, CredentialId, CredentialRelations, CredentialStateEnum, CredentialStateRelations,
};
use crate::model::did::DidId;
use crate::model::revocation_list::{RevocationList, RevocationListId, RevocationListRelations};
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::error::DataLayerError;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::revocation::{CredentialRevocationInfo, RevocationMethod};
use crate::service::error::ServiceError;

pub struct StatusList2021 {
    pub(crate) core_base_url: Option<String>,
    pub(crate) credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
    pub(crate) revocation_list_repository: Arc<dyn RevocationListRepository + Send + Sync>,
}

#[async_trait::async_trait]
impl RevocationMethod for StatusList2021 {
    async fn add_issued_credential(
        &self,
        credential: &Credential,
    ) -> Result<Option<CredentialRevocationInfo>, ServiceError> {
        let issuer_did = credential
            .issuer_did
            .as_ref()
            .ok_or(ServiceError::MappingError("issuer did is None".to_string()))?
            .clone();

        let revocation_list = self
            .revocation_list_repository
            .get_revocation_by_issuer_did_id(&issuer_did.id, &RevocationListRelations::default())
            .await;
        let revocation_list_id = match revocation_list {
            Ok(value) => Ok(value.id),
            Err(DataLayerError::RecordNotFound) => {
                let revocation_bitstring = self
                    .generate_bitstring_from_credentials(&issuer_did.id, None)
                    .await?;

                let now = OffsetDateTime::now_utc();
                Ok(self
                    .revocation_list_repository
                    .create_revocation_list(RevocationList {
                        id: Uuid::new_v4(),
                        created_date: now,
                        last_modified: now,
                        credentials: revocation_bitstring.as_bytes().to_vec(),
                        issuer_did: Some(issuer_did.to_owned()),
                    })
                    .await?)
            }
            Err(error) => Err(error),
        }?;

        let index_on_status_list = self
            .get_credential_index_on_revocation_list(&credential.id, &issuer_did.id)
            .await?;

        Ok(Some(CredentialRevocationInfo {
            additional_vc_contexts: vec!["https://w3id.org/vc/status-list/2021/v1".to_string()],
            credential_status: self
                .create_credential_status(&revocation_list_id, index_on_status_list)?,
        }))
    }

    async fn mark_credential_revoked(&self, credential: &Credential) -> Result<(), ServiceError> {
        let issuer_did = credential
            .issuer_did
            .as_ref()
            .ok_or(ServiceError::MappingError("issuer did is None".to_string()))?
            .clone();

        let revocation_list = self
            .revocation_list_repository
            .get_revocation_by_issuer_did_id(&issuer_did.id, &RevocationListRelations::default())
            .await?;

        let revocation_bitstring = self
            .generate_bitstring_from_credentials(&issuer_did.id, Some(credential.id))
            .await?;

        self.revocation_list_repository
            .update_credentials(
                &revocation_list.id,
                revocation_bitstring.as_bytes().to_vec(),
            )
            .await?;

        Ok(())
    }
}

impl StatusList2021 {
    async fn get_credential_index_on_revocation_list(
        &self,
        credential_id: &CredentialId,
        issuer_did_id: &DidId,
    ) -> Result<usize, DataLayerError> {
        let list = self
            .credential_repository
            .get_credentials_by_issuer_did_id(issuer_did_id, &CredentialRelations::default())
            .await?;

        list.iter()
            .position(|credential| credential.id == *credential_id)
            .ok_or(DataLayerError::RecordNotFound)
    }

    async fn generate_bitstring_from_credentials(
        &self,
        issuer_did_id: &DidId,
        additionally_revoked_credential_id: Option<CredentialId>,
    ) -> Result<String, ServiceError> {
        let credentials = self
            .credential_repository
            .get_credentials_by_issuer_did_id(
                issuer_did_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations {}),
                    ..Default::default()
                },
            )
            .await
            .map_err(ServiceError::from)?;

        let states: Vec<bool> = credentials
            .into_iter()
            .map(|credential| {
                if additionally_revoked_credential_id
                    .is_some_and(|credential_id| credential_id == credential.id)
                {
                    return Ok(true);
                }

                let states = credential
                    .state
                    .ok_or(ServiceError::MappingError("state is None".to_string()))?;

                match states
                    .get(0)
                    .ok_or(ServiceError::MappingError(
                        "latest state not found".to_string(),
                    ))?
                    .state
                {
                    CredentialStateEnum::Revoked => Ok(true),
                    _ => Ok(false),
                }
            })
            .collect::<Result<Vec<bool>, ServiceError>>()?;

        generate_bitstring(states).map_err(ServiceError::from)
    }

    fn create_credential_status(
        &self,
        revocation_list_id: &RevocationListId,
        index_on_status_list: usize,
    ) -> Result<CredentialStatus, ServiceError> {
        let revocation_list_url = format!(
            "{}/ssi/revocation/v1/list/{}",
            self.core_base_url
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "Host URL not specified".to_string()
                ))?,
            revocation_list_id
        );
        Ok(CredentialStatus {
            id: format!("{}#{}", revocation_list_url, index_on_status_list),
            r#type: "StatusList2021Entry".to_string(),
            status_purpose: "revocation".to_string(),
            additional_fields: HashMap::from([
                ("statusListCredential".to_string(), revocation_list_url),
                (
                    "statusListIndex".to_string(),
                    index_on_status_list.to_string(),
                ),
            ]),
        })
    }
}
