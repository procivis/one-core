use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ResolveJsonLDContextQuery {
    pub url: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ResolveJsonLDContextResponseRestDTO {
    pub context: serde_json::Value,
}
