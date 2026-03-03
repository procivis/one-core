use serde::{Deserialize, Serialize};
use shared_types::{CertificateId, IdentifierId, KeyId, OrganisationId, TrustListPublicationId};
use time::OffsetDateTime;

use crate::model::certificate::{Certificate, CertificateRelations};
use crate::model::identifier::{Identifier, IdentifierRelations};
use crate::model::key::{Key, KeyRelations};
use crate::model::organisation::{Organisation, OrganisationRelations};

#[derive(Clone, Debug)]
pub struct TrustListPublication {
    pub id: TrustListPublicationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub role: Option<TrustRoleEnum>,
    pub r#type: TrustListType,
    pub metadata: Vec<u8>,
    pub deactivated_at: Option<OffsetDateTime>,
    pub content: Option<Vec<u8>>,
    pub sequence_number: u64,

    pub organisation_id: Option<OrganisationId>,
    pub identifier_id: Option<IdentifierId>,
    pub key_id: Option<KeyId>,
    pub certificate_id: Option<CertificateId>,

    // Relations
    pub organisation: Option<Organisation>,
    pub identifier: Option<Identifier>,
    pub key: Option<Key>,
    pub certificate: Option<Certificate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustRoleEnum {
    PidProvider,
    WalletProvider,
    WrpAcProvider,
    PubEeaProvider,
    QeaaProvider,
    QesrcProvider,
    WrpRcProvider,
    NationalRegistryRegistrar,
    Issuer,
    Verifier,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustListType {
    Lote,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct TrustListPublicationRelations {
    pub organisation: Option<OrganisationRelations>,
    pub identifier: Option<IdentifierRelations>,
    pub key: Option<KeyRelations>,
    pub certificate: Option<CertificateRelations>,
}
