use futures::future::join_all;
use one_dto_mapper::{convert_inner, convert_inner_of_inner};
use shared_types::{OrganisationId, ProofId};
use standardized_types::openid4vp::dcql::CredentialSet;
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::CredentialSetResponseDTO;
use crate::model::credential::{
    Credential, CredentialFilterValue, CredentialListQuery, CredentialRole, CredentialStateEnum,
    CredentialType,
};
use crate::model::identifier::Identifier;
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::list_filter::ListFilterValue;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::relation::Related;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::error::DataLayerError;

pub(crate) fn interaction_from_handle_invitation(
    data: Option<Vec<u8>>,
    now: OffsetDateTime,
    organisation: impl Into<Related<Organisation>>,
) -> Interaction {
    Interaction {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        data,
        organisation: organisation.into(),
        nonce_id: None,
        interaction_type: InteractionType::Verification,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: None,
    }
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn proof_from_handle_invitation(
    proof_id: &ProofId,
    protocol: &str,
    redirect_uri: Option<String>,
    verifier_identifier: Option<Identifier>,
    interaction: Interaction,
    now: OffsetDateTime,
    transport: &str,
    state: ProofStateEnum,
) -> Proof {
    Proof {
        ecosystem: None,
        id: proof_id.to_owned(),
        created_date: now,
        last_modified: now,
        protocol: protocol.to_owned(),
        redirect_uri,
        transport: transport.to_owned(),
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
) -> Result<Vec<Credential>, DataLayerError> {
    let credentials = credential_repository
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::SchemaId(schema_id).condition()
                    & CredentialFilterValue::OrganisationId(organisation_id)
                    & CredentialFilterValue::States(vec![
                        CredentialStateEnum::Accepted,
                        CredentialStateEnum::Suspended,
                        CredentialStateEnum::Revoked,
                        CredentialStateEnum::Expired,
                    ])
                    & CredentialFilterValue::Roles(vec![CredentialRole::Holder])
                    & CredentialFilterValue::Deleted(false)
                    & (CredentialFilterValue::Types(vec![CredentialType::Single]).condition()
                        | (CredentialFilterValue::Types(vec![CredentialType::BatchParent])
                            .condition()
                            & CredentialFilterValue::HasUnconsumedBatchItems(true))),
            ),
            ..Default::default()
        })
        .await?
        .values;

    Ok(
        join_all(credentials.into_iter().map(|credential| async move {
            match credential_repository.get_credential(&credential.id).await {
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
