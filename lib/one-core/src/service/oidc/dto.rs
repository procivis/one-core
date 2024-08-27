use dto_mapper::Into;
use one_providers::exchange_protocol::openid4vc::model::SubmitIssuerResponse;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, Into)]
#[into(SubmitIssuerResponse)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCICredentialResponseDTO {
    pub credential: String,
    // pub format: String,
    pub redirect_uri: Option<String>,
}
