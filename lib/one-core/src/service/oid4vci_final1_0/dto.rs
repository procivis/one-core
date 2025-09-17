use one_dto_mapper::{From, Into};
use serde::Deserialize;

use crate::provider::issuance_protocol::model::SubmitIssuerResponse;

#[derive(Clone, Debug, Deserialize, Into, From)]
#[into(SubmitIssuerResponse)]
#[from(SubmitIssuerResponse)]
pub struct OpenID4VCICredentialResponseDTO {
    pub credential: String,
    #[serde(rename = "redirectUri")]
    pub redirect_uri: Option<String>,
    pub notification_id: Option<String>,
}
