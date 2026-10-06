use super::{CredentialValidityCheckResult, CredentialValidityManagerImpl, Error};
use crate::error::ContextWithErrorCode;
use crate::model::credential::{
    CredentialStateEnum, CredentialView, HolderCredentialData, UpdateCredentialRequest,
};
use crate::model::credential_schema::CredentialSchema;
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;

impl CredentialValidityManagerImpl {
    pub(super) async fn update_single_mdoc(
        &self,
        credential: &CredentialView<'_, HolderCredentialData>,
        schema: &CredentialSchema,
        force_refresh: bool,
    ) -> Result<CredentialValidityCheckResult, Error> {
        let (_, detail_credential) = self.extract_holder_credential(credential, schema).await?;
        let common = credential.common;

        if !force_refresh && !credential_requires_update(&detail_credential) {
            return Ok(CredentialValidityCheckResult {
                credential_id: common.id,
                status: CredentialStateEnum::Accepted,
                success: true,
                reason: None,
            });
        }

        let interaction = common
            .interaction
            .as_ref()
            .ok_or(Error::MappingError("Missing interaction".to_string()))?
            .as_ref()
            .await?;

        let protocol = self
            .issuance_protocol_provider
            .get_protocol(&common.protocol)?;

        let new_state = match protocol
            .holder_refresh_credential(&interaction, Some(common.id))
            .await
        {
            Ok(_) => CredentialStateEnum::Accepted,
            Err(IssuanceProtocolError::RefreshNotPossible)
                if credential_expired(&detail_credential) =>
            {
                CredentialStateEnum::Expired
            }
            Err(err) => {
                tracing::warn!(%err, "Credential refresh failure");
                if credential_expired(&detail_credential) {
                    CredentialStateEnum::Suspended
                } else {
                    CredentialStateEnum::Accepted
                }
            }
        };

        if new_state != common.state {
            self.credential_repository
                .update_credential(
                    common.id,
                    UpdateCredentialRequest {
                        state: Some(new_state),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating credential")?;
        }

        Ok(CredentialValidityCheckResult {
            credential_id: common.id,
            status: new_state,
            success: true,
            reason: None,
        })
    }
}

fn credential_expired(detail_credential: &DetailCredential) -> bool {
    detail_credential
        .valid_until
        .is_some_and(|valid_until| valid_until < crate::clock::now_utc())
}

fn credential_requires_update(detail_credential: &DetailCredential) -> bool {
    let now = crate::clock::now_utc();

    if let Some(update_at) = detail_credential.update_at {
        return update_at < now;
    }

    credential_expired(detail_credential)
}
