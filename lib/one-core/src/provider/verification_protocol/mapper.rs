use futures::future::join_all;
use one_dto_mapper::{convert_inner, convert_inner_of_inner};
use shared_types::{CredentialId, OrganisationId, ProofId};
use standardized_types::openid4vp::dcql::CredentialSet;
use standardized_types::openid4vp::{VerifierInfoAttestation, VerifierInfoAttestationFormat};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{CredentialSetResponseDTO, InvitationRequest};
use super::error::VerificationProtocolError;
use crate::clock::now_utc;
use crate::config::core_config::BlobStorageType;
use crate::error::ContextWithErrorCode;
use crate::model::blob::BlobType;
use crate::model::common::SortDirection;
use crate::model::credential::{
    Credential, CredentialFilterValue, CredentialListQuery, CredentialRole, CredentialStateEnum,
    CredentialType, SortableCredentialColumn,
};
use crate::model::identifier::Identifier;
use crate::model::identifier_trust_information::IdentifierTrustInformation;
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::list_filter::{ComparisonType, ListFilterValue, ValueComparison};
use crate::model::list_query::ListSorting;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::relation::Related;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::error::DataLayerError;
use crate::service::ssi_holder::dto::HandleInvitationRequestDataDTO;

pub(super) fn interaction_from_handle_invitation(
    data: Option<Vec<u8>>,
    now: OffsetDateTime,
    organisation: impl Into<Related<Organisation>>,
) -> Interaction {
    Interaction {
        dpop_key: None,
        client_attestation_key: None,
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        data,
        organisation: organisation.into(),
        interaction_type: InteractionType::Verification,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    }
}

pub(super) fn proof_from_handle_invitation(
    proof_id: ProofId,
    protocol: &str,
    verifier_identifier: Option<Identifier>,
    interaction: Interaction,
    transport: String,
) -> Proof {
    let now = now_utc();
    Proof {
        id: proof_id,
        created_date: now,
        last_modified: now,
        protocol: protocol.to_owned(),
        redirect_uri: None,
        transport,
        state: ProofStateEnum::Requested,
        role: ProofRole::Holder,
        requested_date: Some(now),
        completed_date: None,
        profile: None,
        schema: None,
        claims: Default::default(),
        verifier_identifier: convert_inner(verifier_identifier),
        interaction: Some(interaction.into()),
        verifier_key: None,
        verifier_certificate: None,
        proof_blob_id: None,
        engagement: None,
        webhook_url: None,
        subscriber_information: None,
        ecosystem: None,
    }
}

impl From<CredentialSet> for CredentialSetResponseDTO {
    fn from(value: CredentialSet) -> Self {
        Self {
            required: value.required,
            options: convert_inner_of_inner(value.options),
        }
    }
}

pub(super) async fn get_presentation_credentials_by_schema_id(
    credential_repository: &dyn CredentialRepository,
    schema_id: String,
    organisation_id: OrganisationId,
    submitted_credential_ids: &[CredentialId],
) -> Result<Vec<Credential>, DataLayerError> {
    let mut candidates = CredentialFilterValue::Types(vec![CredentialType::Single]).condition()
        | CredentialFilterValue::EarliestExpiringBatchItemPerFormat;
    if !submitted_credential_ids.is_empty() {
        // Explicit items need not be the per-format representative. For parent IDs,
        // historical matches distinguish exhausted batches from unrelated batches.
        let unavailable_items = CredentialFilterValue::Consumed(true).condition()
            | CredentialFilterValue::States(vec![
                CredentialStateEnum::Suspended {
                    suspend_end_date: None,
                },
                CredentialStateEnum::Revoked,
                CredentialStateEnum::Expired,
            ])
            | CredentialFilterValue::ExpiresAt(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: now_utc(),
            });
        let submitted_items =
            CredentialFilterValue::CredentialIds(submitted_credential_ids.to_vec()).condition()
                | (CredentialFilterValue::ParentCredentials(submitted_credential_ids.to_vec())
                    .condition()
                    & unavailable_items);
        candidates = candidates
            | (CredentialFilterValue::Types(vec![CredentialType::BatchItem]).condition()
                & submitted_items);
    }
    let credentials = credential_repository
        .get_credential_list(CredentialListQuery {
            include_count: false,
            filtering: Some(
                CredentialFilterValue::SchemaId(schema_id).condition()
                    & CredentialFilterValue::OrganisationId(organisation_id)
                    & CredentialFilterValue::States(vec![
                        CredentialStateEnum::Accepted,
                        CredentialStateEnum::Suspended {
                            suspend_end_date: None,
                        },
                        CredentialStateEnum::Revoked,
                        CredentialStateEnum::Expired,
                    ])
                    & CredentialFilterValue::Roles(vec![CredentialRole::Holder])
                    & CredentialFilterValue::Deleted(false)
                    & candidates,
            ),
            sorting: Some(ListSorting {
                column: SortableCredentialColumn::CreatedDate,
                direction: Some(SortDirection::Ascending),
            }),
            ..Default::default()
        })
        .await?
        .values;

    Ok(
        join_all(credentials.into_iter().map(|credential| async move {
            match credential_repository
                .get_credential(&credential.common().id)
                .await
            {
                Ok(credential) => Ok(Some(credential)),
                Err(DataLayerError::EntityNotFound { .. }) => Ok(None),
                Err(error) => Err(error),
            }
        }))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect(),
    )
}

impl From<HandleInvitationRequestDataDTO> for InvitationRequest {
    fn from(data: HandleInvitationRequestDataDTO) -> Self {
        match data {
            HandleInvitationRequestDataDTO::Url { url } => Self::Url(url),
            HandleInvitationRequestDataDTO::Iso18013DcApi {
                device_request,
                encryption_info,
                origin,
                response_handler,
            } => Self::IsoDcApi {
                origin,
                encryption_info,
                device_request,
                response_handler,
            },
            HandleInvitationRequestDataDTO::OpenID4vpDcApi {
                origin,
                request_json,
                response_handler,
            } => Self::OpenID4VpDcApi {
                origin,
                request_json,
                response_handler,
            },
        }
    }
}

/// Resolves all IdentifierTrustInformation entries for an identifier
/// A VerifierInfoAttestation struct with the resolved registration certificate
/// is returned for each valid entry
pub(crate) async fn gather_registration_certificates(
    identifier: &Identifier,
    blob_storage_provider: &dyn BlobStorageProvider,
) -> Result<Vec<(IdentifierTrustInformation, VerifierInfoAttestation)>, VerificationProtocolError> {
    let trust_information = identifier.trust_information.as_ref().await?;

    let now = now_utc();
    let valid_registration_certificates: Vec<&IdentifierTrustInformation> = trust_information
        .iter()
        .filter(|entry| {
            if entry.allowed_verification_types.is_empty() {
                return false;
            }

            if let Some(valid_from) = entry.valid_from
                && valid_from > now
            {
                return false;
            }

            if let Some(valid_to) = entry.valid_to
                && valid_to < now
            {
                return false;
            }

            true
        })
        .collect();

    if valid_registration_certificates.is_empty() {
        return Ok(vec![]);
    }

    let blob_storage = blob_storage_provider.get_blob_storage(BlobStorageType::Db)?;

    let mut result = vec![];

    for entry in valid_registration_certificates {
        let certificate = blob_storage
            .get(&entry.blob_id)
            .await
            .error_while("resolving trust_information blob")?
            .ok_or(VerificationProtocolError::TrustInformationError(
                "Missing registration certificate".to_string(),
            ))?;

        if certificate.r#type != BlobType::RegistrationCertificate {
            return Err(VerificationProtocolError::TrustInformationError(format!(
                "Invalid trust information data, expected registration certificate, got {:?}",
                certificate.r#type
            )));
        }

        result.push((
            entry.to_owned(),
            VerifierInfoAttestation {
                format: VerifierInfoAttestationFormat::RegistrationCert,
                data: String::from_utf8(certificate.value)
                    .map_err(|e| VerificationProtocolError::TrustInformationError(e.to_string()))?,
                credential_ids: vec![],
            },
        ))
    }

    Ok(result)
}
