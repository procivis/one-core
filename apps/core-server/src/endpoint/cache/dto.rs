use one_dto_mapper::{From, Into};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from("one_core::model::remote_entity_cache::CacheType")]
#[into("one_core::model::remote_entity_cache::CacheType")]
pub enum CacheTypeRestEnum {
    DidDocument,
    JsonLdContext,
    StatusListCredential,
    VctMetadata,
    JsonSchema,
    TrustList,
}

#[derive(Clone, Deserialize, Debug, Default, IntoParams, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct DeleteCacheQuery {
    #[param(rename = "types[]", inline, nullable = false)]
    pub types: Option<Vec<CacheTypeRestEnum>>,
}
