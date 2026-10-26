use one_dto_mapper::{From, Into};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from("one_core::model::remote_entity_cache::CacheType")]
#[into("one_core::model::remote_entity_cache::CacheType")]
pub(crate) enum CacheTypeRestEnum {
    DidDocument,
    JsonLdContext,
    /// Credential status list fetched from an external source.
    StatusListCredential,
    /// Metadata for SD-JWT VC type (VCT).
    VctMetadata,
    JsonSchema,
    TrustList,
    /// X.509 certificate revocation list.
    X509Crl,
    /// Certificate revocation list used for Android key attestation.
    AndroidAttestationCrl,
    /// OpenID provider metadata fetched by holder.
    #[serde(rename = "OPENID_METADATA_HOLDER")]
    OpenIdMetadataHolder,
    /// OpenID provider metadata cached/served by issuer.
    #[serde(rename = "OPENID_METADATA_ISSUER")]
    OpenIdMetadataIssuer,
    /// Metadata fetched from the registered wallet provider.
    WalletProviderMetadata,
    /// Trust collection data fetched from a remote source.
    RemoteTrustCollection,
}

#[derive(Clone, Deserialize, Debug, Default, IntoParams, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub(crate) struct DeleteCacheQuery {
    #[param(rename = "types[]", inline)]
    pub types: Option<Vec<CacheTypeRestEnum>>,
}
