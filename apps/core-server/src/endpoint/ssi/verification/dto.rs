use std::collections::HashMap;

use one_core::provider::verification_protocol::openid4vp::model::{
    OpenID4VPDirectPostRequestDTO, VpSubmissionData,
};
use one_dto_mapper::{From, Into};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use serde_with::json::JsonString;
use serde_with::serde_as;
use shared_types::InteractionId;
use standardized_types::openid4vp::{DirectPostResponse, EncryptedResponse, VpTokenResponse};
use utoipa::ToSchema;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(OpenID4VPDirectPostRequestDTO)]
pub(crate) struct OpenID4VPDirectPostRequestRestDTO {
    #[serde(flatten)] // Prevents using deny_unknown_fields
    pub submission_data: VpSubmissionDataRestDTO,
    #[schema(example = "3fa85f64-5717-4562-b3fc-2c963f66afa6")]
    pub state: Option<InteractionId>,
}

/// Represents the different types of VP token submissions supported by OpenID4VP.
/// Untagged serialization automatically detects the submission type.
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(VpSubmissionData)]
#[serde(untagged)]
pub(crate) enum VpSubmissionDataRestDTO {
    /// DCQL submission with vp_token map structure
    Unencrypted(DcqlSubmissionRestDTO),
    /// Response submission with response field (JWE encrypted payload)
    Encrypted(ResponseSubmissionRestDTO),
}

#[serde_as]
#[derive(Debug, Deserialize, Clone, ToSchema, Into)]
#[into(VpTokenResponse)]
pub(crate) struct DcqlSubmissionRestDTO {
    #[serde_as(as = "JsonString")]
    pub vp_token: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize, Clone, ToSchema, Into)]
#[into(EncryptedResponse)]
pub(crate) struct ResponseSubmissionRestDTO {
    pub response: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(DirectPostResponse)]
pub(crate) struct OpenID4VPDirectPostResponseRestDTO {
    pub redirect_uri: Option<String>,
}
