use futures::future::join_all;
use one_dto_mapper::{convert_inner, convert_inner_of_inner};
use shared_types::{CredentialId, OrganisationId, ProofId};
use standardized_types::openid4vp::dcql::CredentialSet;
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{CredentialSetResponseDTO, InvitationRequest};
use crate::model::common::SortDirection;
use crate::model::credential::{
    Credential, CredentialFilterValue, CredentialListQuery, CredentialRole, CredentialStateEnum,
    CredentialType, SortableCredentialColumn,
};
use crate::model::identifier::Identifier;
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::list_filter::{ComparisonType, ListFilterValue, ValueComparison};
use crate::model::list_query::ListSorting;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::relation::Related;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::error::DataLayerError;
use crate::service::ssi_holder::dto::HandleInvitationRequestDataDTO;

pub(crate) fn interaction_from_handle_invitation(
    data: Option<Vec<u8>>,
    now: OffsetDateTime,
    organisation: impl Into<Related<Organisation>>,
) -> Interaction {
    Interaction {
        dpop_key: None,
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

#[expect(clippy::too_many_arguments)]
pub(crate) fn proof_from_handle_invitation(
    proof_id: ProofId,
    protocol: &str,
    redirect_uri: Option<String>,
    verifier_identifier: Option<Identifier>,
    interaction: Interaction,
    now: OffsetDateTime,
    transport: String,
    state: ProofStateEnum,
) -> Proof {
    Proof {
        id: proof_id,
        created_date: now,
        last_modified: now,
        protocol: protocol.to_owned(),
        redirect_uri,
        transport,
        state,
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

pub(crate) async fn get_presentation_credentials_by_schema_id(
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
                value: crate::clock::now_utc(),
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

impl TryFrom<HandleInvitationRequestDataDTO> for InvitationRequest {
    type Error = VerificationProtocolError;

    fn try_from(data: HandleInvitationRequestDataDTO) -> Result<Self, Self::Error> {
        Ok(match data {
            HandleInvitationRequestDataDTO::Url { url } => InvitationRequest::Url(url),
            HandleInvitationRequestDataDTO::Iso18013DcApi {
                device_request,
                encryption_info,
                origin,
                response_handler,
            } => InvitationRequest::IsoDcApi {
                origin,
                encryption_info,
                device_request,
                response_handler,
            },
            HandleInvitationRequestDataDTO::OpenID4vpDcApi { .. } => {
                return Err(VerificationProtocolError::Failed(
                    "OpenID4VP DC-API not yet supported".to_string(),
                ));
            }
        })
    }
}
