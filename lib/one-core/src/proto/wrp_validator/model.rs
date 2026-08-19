use serde::Deserialize;
use serde_with::{OneOrMany, serde_as};
use standardized_types::etsi_119_475::Credential;
use standardized_types::etsi_119_475::registration_certificate::Payload;
use standardized_types::etsi_119_475::registry::{
    Identifier, IntendedUse, LegalEntity, LegalPerson, MultiLangString, NaturalPerson,
    WalletRelyingParty,
};
use standardized_types::jwk::PublicJwk;
use url::Url;

use crate::proto::jwt::model::JWTPayload;
use crate::provider::trust_list_subscriber::TrustEntityResponse;

pub(crate) struct AccessCertificateResult {
    #[expect(unused)]
    pub trust_entity: Option<TrustEntityResponse>,
    pub relying_party_id: String,
    pub registry_url: Option<Url>,
}

pub(crate) struct RegistrationCertificateResult {
    #[expect(unused)]
    pub trust_entity: Option<TrustEntityResponse>,
    pub payload: JWTPayload<Payload>,
}

pub(crate) struct FetchRegistryResult {
    #[expect(unused)]
    pub trust_entity: Option<TrustEntityResponse>,
    pub payload: JWTPayload<WRPPayload>,
    pub jwt: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(super) struct RegistryKeys {
    pub keys: Vec<PublicJwk>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WRPPayload {
    pub data: WRPPayloadData,
}

/// temporary JWT payload, until it is clearly defined
/// matches <https://gitlab.procivis.ch/procivis/one/one-java-commons/-/blob/main/one-public-api/src/main/java/com/procivis/pub/api/wrpr/dto/PublicWalletRelyingPartyDTO.java>
///
/// A flattened variant of [`WalletRelyingParty`] (ETSI TS 119 475 annex B.2.1) with the
/// [`LegalEntity`] fields of the relying party itself lifted to the top level.
#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WRPPayloadData {
    pub trade_name: Option<String>,
    #[serde(rename = "supportURI")]
    pub support_uri: Vec<Url>,
    pub srv_description: Vec<MultiLangString>,
    #[serde(default)]
    pub intended_use: Vec<IntendedUse>,
    #[serde(default, rename = "isPSB")]
    pub is_psb: Option<bool>,
    pub entitlement: Vec<String>,
    #[serde(default)]
    pub provides_attestations: Vec<Credential>,
    pub supervisory_authority: LegalEntity,
    #[serde(rename = "registryURI")]
    #[expect(unused)]
    pub registry_uri: Url,
    pub uses_intermediary: Option<Vec<WalletRelyingParty>>,
    #[expect(unused)]
    pub legal_person: Option<LegalPerson>,
    #[expect(unused)]
    pub natural_person: Option<NaturalPerson>,
    #[serde(default)]
    #[expect(unused)]
    pub identifier: Vec<Identifier>,
    #[serde(default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    #[expect(unused)]
    pub postal_address: Option<Vec<String>>,
    pub country: String,
    #[serde(default)]
    pub email: Vec<String>,
    #[serde(default)]
    pub phone: Vec<String>,
    #[serde(default, rename = "infoURI")]
    #[expect(unused)]
    pub info_uri: Vec<Url>,
}
