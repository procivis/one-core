use one_dto_mapper::{From, Into};
use serde::Deserialize;

use crate::provider::issuance_protocol::openid4vci_draft13::model::SubmitIssuerResponse;

#[derive(Clone, Debug, Deserialize, Into, From)]
#[into(SubmitIssuerResponse)]
#[from(SubmitIssuerResponse)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCICredentialResponseDTO {
    pub credential: String,
    pub redirect_uri: Option<String>,
}
