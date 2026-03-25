use one_core::service::verifier_instance::dto;
use one_dto_mapper::{From, Into};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{OrganisationId, TrustCollectionId, VerifierInstanceId};
use utoipa::ToSchema;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::RegisterVerifierInstanceRequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterVerifierInstanceRequestRestDTO {
    pub organisation_id: OrganisationId,
    pub verifier_provider_url: String,
    pub r#type: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(dto::RegisterVerifierInstanceResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct RegisterVerifierInstanceResponseRestDTO {
    pub id: VerifierInstanceId,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::EditVerifierInstanceRequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EditVerifierInstanceRequestRestDTO {
    pub trust_collections: Vec<TrustCollectionId>,
}
