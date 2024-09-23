use dto_mapper::Into;
use serde::Deserialize;

use crate::provider::exchange_protocol::openid4vc::model::SubmitIssuerResponse;

#[derive(Clone, Debug, Deserialize, Into)]
#[into(SubmitIssuerResponse)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCICredentialResponseDTO {
    pub credential: String,
    pub format: String,
    pub redirect_uri: Option<String>,
}
