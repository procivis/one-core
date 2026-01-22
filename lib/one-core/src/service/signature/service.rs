use std::collections::HashMap;

use one_dto_mapper::convert_inner;
use time::OffsetDateTime;
use uuid::Uuid;

use super::SignatureService;
use crate::error::ContextWithErrorCode;
use crate::model::certificate::CertificateRelations;
use crate::model::did::DidRelations;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
};
use crate::model::identifier::IdentifierRelations;
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::revocation_list::{RevocationListEntityInfo, RevocationListRelations};
use crate::provider::signer::dto::{
    CreateSignatureRequestDTO, CreateSignatureResponseDTO, RevocationInfo,
};
use crate::service::signature::dto::SignatureStatusInfo;
use crate::service::signature::error::SignatureServiceError;
use crate::util::key_selection::KeySelection;
use crate::validator::{
    throw_if_org_not_matching_session, throw_if_org_relation_not_matching_session,
};

impl SignatureService {
    pub async fn sign(
        &self,
        request: CreateSignatureRequestDTO,
    ) -> Result<CreateSignatureResponseDTO, SignatureServiceError> {
        let Some(signer) = self.signer_provider.get(request.signer.as_str()) else {
            return Err(SignatureServiceError::MissingSignerProvider(request.signer));
        };
        let signature_type = request.signer.to_owned();
        let issuer = self
            .identifier_repository
            .get(
                request.issuer,
                &IdentifierRelations {
                    organisation: Some(OrganisationRelations::default()),
                    did: Some(DidRelations {
                        keys: Some(KeyRelations { organisation: None }),
                        organisation: None,
                    }),
                    key: Some(KeyRelations { organisation: None }),
                    certificates: Some(CertificateRelations {
                        key: Some(KeyRelations { organisation: None }),
                        organisation: None,
                    }),
                },
            )
            .await
            .error_while("Loading issuer identifier")?
            .ok_or(SignatureServiceError::IdentifierNotFound(request.issuer))?;
        let organisation_id = issuer
            .organisation
            .as_ref()
            .ok_or(SignatureServiceError::MappingError(
                "organisation is None".to_string(),
            ))?
            .id;
        // TODO ONE-8416: Permission check
        throw_if_org_not_matching_session(&organisation_id, &*self.session_provider)
            .error_while("validating organisation")?;
        let issuer_id = issuer.id;

        let selection = issuer
            .select_key(KeySelection {
                key: request.issuer_key,
                certificate: request.issuer_certificate,
                ..Default::default()
            })
            .error_while("Selecting signing key")?;

        let revocation_info = if let Some(revocation_method) = signer.revocation_method() {
            let (id, revocation_info) = revocation_method
                .add_signature(
                    request.signer.clone(),
                    &issuer,
                    &selection.certificate().cloned(),
                )
                .await
                .error_while("Adding signature to revocation list")?;
            Some(RevocationInfo {
                id,
                status: revocation_info.credential_status,
                serial: revocation_info.serial,
            })
        } else {
            None
        };

        let request_data = request.data.clone();
        let result = signer
            .sign(issuer, request, revocation_info)
            .await
            .error_while("signing signature request")?;

        if let Err(error) = self
            .history
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                source: HistorySource::Core,
                action: HistoryAction::Created,
                entity_id: Some(result.id.into()),
                entity_type: HistoryEntityType::Signature,
                metadata: Some(HistoryMetadata::External(request_data)),
                name: signature_type.to_owned(),
                target: Some(issuer_id.to_string()),
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().map(|s| s.user_id),
            })
            .await
        {
            tracing::warn!("Failed to write history entry: {}", error);
        }

        tracing::info!(
            "Created signature {} using identifier {}: signature type `{}`",
            result.id,
            issuer_id,
            signature_type
        );
        Ok(result)
    }

    pub async fn revoke(&self, id: Uuid) -> Result<(), SignatureServiceError> {
        let (signer_name, signer) = self
            .signer_provider
            .get_for_signature_id(id)
            .await
            .error_while("getting signer provider")?;
        let Some(revocation_method) = signer.revocation_method() else {
            return Err(SignatureServiceError::RevocationNotSupported);
        };
        let list = self
            .revocation_list_repository
            .get_revocation_list_by_entry_id(
                id.into(),
                &RevocationListRelations {
                    issuer_identifier: Some(IdentifierRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting revocation list entries")?
            .ok_or(SignatureServiceError::InvalidSignatureId(id))?;
        let issuer = list
            .issuer_identifier
            .as_ref()
            .ok_or(SignatureServiceError::MappingError(
                "Missing revocation list issuer".to_string(),
            ))?;
        // TODO ONE-8416: Permission check
        throw_if_org_relation_not_matching_session(
            issuer.organisation.as_ref(),
            &*self.session_provider,
        )
        .error_while("validating organisation")?;

        revocation_method
            .revoke_signature(id.into())
            .await
            .error_while("revoking signature")?;

        if let Err(error) = self
            .history
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                source: HistorySource::Core,
                action: HistoryAction::Revoked,
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::Signature,
                metadata: None,
                name: signer_name,
                target: Some(issuer.id.to_string()),
                organisation_id: None,
                user: self.session_provider.session().map(|s| s.user_id),
            })
            .await
        {
            tracing::warn!("Failed to write history entry: {}", error);
        }

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
