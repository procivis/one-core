use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiIssuerConnectQuery {
    pub protocol: String,
    pub credential: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectRequestDTO {
    pub did: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct HandleInvitationRequestDTO {
    pub url: String,
}
