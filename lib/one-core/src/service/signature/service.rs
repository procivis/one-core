use std::collections::HashMap;

use one_dto_mapper::convert_inner;
use uuid::Uuid;

use super::SignatureService;
use crate::error::ContextWithErrorCode;
use crate::model::revocation_list::RevocationListEntityInfo;
use crate::provider::signer::dto::{CreateSignatureRequestDTO, CreateSignatureResponseDTO};
use crate::service::signature::dto::SignatureStatusInfo;
use crate::service::signature::error::SignatureServiceError;

impl SignatureService {
    pub async fn sign(
        &self,
        request: CreateSignatureRequestDTO,
    ) -> Result<CreateSignatureResponseDTO, SignatureServiceError> {
        let signature_type = request.signer.to_owned();
        let identifier = request.issuer;
        let result = match self.signer_provider.get_from_type(request.signer.as_str()) {
            Some(signer) => signer
                .sign(request)
                .await
                .error_while("signing signature request")?,
            None => {
                return Err(SignatureServiceError::MissingSignerProvider(request.signer));
            }
        };
        tracing::info!(
            "Created signature {} using identifier {identifier}: signature type `{}`",
            result.id,
            signature_type
        );
        Ok(result)
    }

    pub async fn revoke(&self, id: Uuid) -> Result<(), SignatureServiceError> {
        self.signer_provider
            .get_for_signature_id(id)
            .await
            .error_while("getting signer provider")?
            .revoke(id)
            .await
            .error_while("revoking signature")?;
        tracing::info!("Revoked signature {}", id);
        Ok(())
    }

    pub async fn revocation_check(
        &self,
        signature_ids: Vec<Uuid>,
    ) -> Result<HashMap<Uuid, SignatureStatusInfo>, SignatureServiceError> {
        let entries = self
            .revocation_list_repository
            .get_entries_by_id(convert_inner(signature_ids))
            .await
            .error_while("getting revocation list entries")?;
        let mut result = HashMap::new();
        for entry in entries {
            let RevocationListEntityInfo::Signature(r#type, _) = entry.entity_info else {
                return Err(SignatureServiceError::InvalidSignatureId(entry.id.into()));
            };
            result.insert(
                entry.id.into(),
                SignatureStatusInfo {
                    state: entry.status.try_into()?,
                    r#type,
                },
            );
        }
        Ok(result)
    }
}
