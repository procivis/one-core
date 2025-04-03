use one_dto_mapper::Into;
use serde::Deserialize;

use crate::provider::issuance_protocol::openid4vc::model::SubmitIssuerResponse;

#[derive(Clone, Debug, Deserialize, Into)]
#[into(SubmitIssuerResponse)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCICredentialResponseDTO {
    pub credential: String,
    pub redirect_uri: Option<String>,
}
