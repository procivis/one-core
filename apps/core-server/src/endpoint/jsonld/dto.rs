use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Debug, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ResolveJsonLDContextQuery {
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ResolveJsonLDContextResponseRestDTO {
    pub context: serde_json::Value,
}
