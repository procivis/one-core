use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{common_mapper::deserialize_with_serde_json, model::claim_schema::ClaimSchemaId};

// Equivalent of transport_protocol/openid4vc/model.rs for deserialization
// to avoid dependency to the transport protocol itself
#[derive(Clone, Deserialize, Serialize, Debug)]
pub(super) struct OpenID4VPInteractionContent {
    pub nonce: String,
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: OpenID4VPPresentationDefinition,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPPresentationDefinition {
    pub id: Uuid,
    pub input_descriptors: Vec<OpenID4VPPresentationDefinitionInputDescriptor>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPPresentationDefinitionInputDescriptor {
    pub id: String,
    pub constraints: OpenID4VPPresentationDefinitionConstraint,
}
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPPresentationDefinitionConstraint {
    pub fields: Vec<OpenID4VPPresentationDefinitionConstraintField>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPPresentationDefinitionConstraintField {
    pub id: ClaimSchemaId,
    pub path: Vec<String>,
    pub optional: bool,
}
