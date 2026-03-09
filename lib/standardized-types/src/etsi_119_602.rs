//! ETSI TS 119 602 — List of Trusted Entities (LoTE)
//!
//! JSON binding types for the LoTE trust list format.
//! Spec: <https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf>

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use strum::Display;

/// LoTE type URIs per ETSI TS 119 602 Annex C.
#[derive(Clone, Debug, PartialEq, Eq, Display)]
pub enum LoTEType {
    #[strum(to_string = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList")]
    EuPidProvidersList,
    #[strum(to_string = "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList")]
    EuWalletProvidersList,
    #[strum(to_string = "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList")]
    EuWrpAcProvidersList,
    #[strum(to_string = "http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList")]
    EuWrpRcProvidersList,
    #[strum(to_string = "http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList")]
    EuPubEaaProvidersList,
    #[strum(to_string = "http://uri.etsi.org/19602/LoTEType/EURegistrarsAndRegistersList")]
    EuRegistrarsAndRegistersList,
}

impl LoTEType {
    /// StatusDeterminationApproach URI, annex C.2.2
    pub fn status_determination_approach(&self) -> &'static str {
        match self {
            Self::EuPidProvidersList => "http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU",
            Self::EuWalletProvidersList => {
                "http://uri.etsi.org/19602/WalletProvidersList/StatusDetn/EU"
            }
            Self::EuWrpAcProvidersList => {
                "http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU"
            }
            Self::EuWrpRcProvidersList => {
                "http://uri.etsi.org/19602/WRPRCProvidersList/StatusDetn/EU"
            }
            Self::EuPubEaaProvidersList => {
                "http://uri.etsi.org/19602/PubEAAProvidersList/StatusDetn/EU"
            }
            Self::EuRegistrarsAndRegistersList => {
                "http://uri.etsi.org/19602/RegistrarsAndRegistersList/StatusDetn/EU"
            }
        }
    }

    /// SchemeTypeCommunityRules URI, annex C.2.3
    pub fn scheme_type_community_rules(&self) -> &'static str {
        match self {
            Self::EuPidProvidersList => "http://uri.etsi.org/19602/PIDProviders/schemerules/EU",
            Self::EuWalletProvidersList => {
                "http://uri.etsi.org/19602/WalletProvidersList/schemerules/EU"
            }
            Self::EuWrpAcProvidersList => {
                "http://uri.etsi.org/19602/WRPACProvidersList/schemerules/EU"
            }
            Self::EuWrpRcProvidersList => {
                "http://uri.etsi.org/19602/WRPRCProvidersList/schemerules/EU"
            }
            Self::EuPubEaaProvidersList => {
                "http://uri.etsi.org/19602/PubEAAProvidersList/schemerules/EU"
            }
            Self::EuRegistrarsAndRegistersList => {
                "http://uri.etsi.org/19602/RegistrarsAndRegistersList/schemerules/EU"
            }
        }
    }

    /// SchemeTerritory — always "EU" for EU profiles.
    pub fn scheme_territory(&self) -> &'static str {
        "EU"
    }

    /// Service type identifier URIs for this EU profile.
    /// Annexes D.1,2,3
    pub fn service_type_identifiers(&self) -> Vec<(&'static str, &'static str)> {
        match self {
            Self::EuPidProvidersList => vec![
                (
                    "http://uri.etsi.org/19602/SvcType/PID/Issuance",
                    "PID Issuance",
                ),
                (
                    "http://uri.etsi.org/19602/SvcType/PID/Revocation",
                    "PID Revocation",
                ),
            ],
            Self::EuWalletProvidersList => vec![
                (
                    "http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance",
                    "Wallet Solution Issuance",
                ),
                (
                    "http://uri.etsi.org/19602/SvcType/WalletSolution/Revocation",
                    "Wallet Solution Revocation",
                ),
            ],
            Self::EuWrpAcProvidersList => vec![
                (
                    "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance",
                    "WRPAC Issuance",
                ),
                (
                    "http://uri.etsi.org/19602/SvcType/WRPAC/Revocation",
                    "WRPAC Revocation",
                ),
            ],
            Self::EuWrpRcProvidersList => vec![
                (
                    "http://uri.etsi.org/19602/SvcType/WRPRC/Issuance",
                    "WRPRC Issuance",
                ),
                (
                    "http://uri.etsi.org/19602/SvcType/WRPRC/Revocation",
                    "WRPRC Revocation",
                ),
            ],
            Self::EuPubEaaProvidersList => vec![
                (
                    "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance",
                    "PubEAA Issuance",
                ),
                (
                    "http://uri.etsi.org/19602/SvcType/PubEAA/Revocation",
                    "PubEAA Revocation",
                ),
            ],
            Self::EuRegistrarsAndRegistersList => {
                vec![("http://uri.etsi.org/19602/SvcType/Register", "Register")]
            }
        }
    }
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LoTEPayload {
    pub list_and_scheme_information: ListAndSchemeInformation,
    #[serde(rename = "TrustedEntitiesList")]
    pub trusted_entities_list: Option<Vec<TrustedEntity>>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListAndSchemeInformation {
    #[serde(rename = "LoTEVersionIdentifier")]
    pub lote_version_identifier: u64,

    #[serde(rename = "LoTESequenceNumber")]
    pub lote_sequence_number: u64,

    #[serde(rename = "LoTEType")]
    pub lote_type: String,

    #[serde(rename = "SchemeOperatorName")]
    pub scheme_operator_name: Vec<MultiLangString>,

    #[serde(rename = "SchemeInformationURI")]
    pub scheme_information_uri: Option<Vec<MultiLangUri>>,

    #[serde(rename = "StatusDeterminationApproach")]
    pub status_determination_approach: String,

    #[serde(rename = "SchemeTypeCommunityRules")]
    pub scheme_type_community_rules: Option<Vec<MultiLangUri>>,

    #[serde(rename = "SchemeTerritory")]
    pub scheme_territory: String,

    #[serde(rename = "SchemeOperatorAddress")]
    pub scheme_operator_address: Option<SchemeOperatorAddress>,

    #[serde(rename = "SchemeName")]
    pub scheme_name: Option<Vec<MultiLangString>>,

    #[serde(rename = "PolicyOrLegalNotice")]
    pub policy_or_legal_notice: Option<Vec<PolicyOrLegalNoticeItem>>,

    #[serde(rename = "HistoricalInformationPeriod")]
    pub historical_information_period: Option<u64>,

    #[serde(rename = "PointersToOtherLoTE")]
    pub pointers_to_other_lote: Option<Vec<OtherLoTEPointer>>,

    #[serde(rename = "DistributionPoints")]
    pub distribution_points: Option<Vec<String>>,

    #[serde(rename = "SchemeExtensions")]
    pub scheme_extensions: Option<Vec<serde_json::Value>>,

    #[serde(rename = "ListIssueDateTime")]
    pub list_issue_date_time: String,

    #[serde(rename = "NextUpdate")]
    pub next_update: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedEntity {
    #[serde(rename = "TrustedEntityInformation")]
    pub trusted_entity_information: TrustedEntityInformation,

    #[serde(rename = "TrustedEntityServices")]
    pub trusted_entity_services: Vec<TrustedEntityService>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TrustedEntityInformation {
    #[serde(rename = "TEName")]
    pub te_name: Vec<MultiLangString>,

    #[serde(rename = "TEInformationURI")]
    pub te_information_uri: Option<Vec<MultiLangUri>>,

    #[serde(rename = "TEAddress")]
    pub te_address: Option<TEAddress>,

    #[serde(rename = "TETradeName")]
    pub te_trade_name: Option<Vec<MultiLangString>>,

    #[serde(rename = "TEInformationExtensions")]
    pub te_information_extensions: Option<Vec<serde_json::Value>>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TEAddress {
    #[serde(rename = "TEElectronicAddress")]
    pub te_electronic_address: Option<Vec<MultiLangUri>>,

    #[serde(rename = "TEPostalAddress")]
    pub te_postal_address: Option<Vec<PostalAddress>>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostalAddress {
    pub lang: String,
    #[serde(rename = "Country")]
    pub country: String,
    #[serde(rename = "Locality")]
    pub locality: Option<String>,
    #[serde(rename = "PostalCode")]
    pub postal_code: Option<String>,
    #[serde(rename = "StreetAddress")]
    pub street_address: String,
    #[serde(rename = "StateOrProvince")]
    pub state_or_province: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TrustedEntityService {
    #[serde(rename = "ServiceInformation")]
    pub service_information: ServiceInformation,

    #[serde(rename = "ServiceHistory")]
    pub service_history: Option<Vec<ServiceHistoryInstance>>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServiceInformation {
    #[serde(rename = "ServiceTypeIdentifier")]
    pub service_type_identifier: String,

    #[serde(rename = "ServiceName")]
    pub service_name: Vec<MultiLangString>,

    #[serde(rename = "ServiceDigitalIdentity")]
    pub service_digital_identity: Option<ServiceDigitalIdentity>,

    #[serde(rename = "ServiceStatus")]
    pub service_status: Option<String>,

    #[serde(rename = "StatusStartingTime")]
    pub status_starting_time: Option<String>,

    #[serde(rename = "SchemeServiceDefinitionURI")]
    pub scheme_service_definition_uri: Option<Vec<MultiLangUri>>,

    #[serde(rename = "ServiceSupplyPoints")]
    pub service_supply_points: Option<Vec<ServiceSupplyPoint>>,

    #[serde(rename = "ServiceDefinitionURI")]
    pub service_definition_uri: Option<Vec<MultiLangUri>>,

    #[serde(rename = "ServiceInformationExtensions")]
    pub service_information_extensions: Option<Vec<serde_json::Value>>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServiceDigitalIdentity {
    #[serde(rename = "X509Certificates")]
    pub x509_certificates: Option<Vec<PkiObject>>,

    #[serde(rename = "X509SubjectNames")]
    pub x509_subject_names: Option<Vec<String>>,

    #[serde(rename = "PublicKeyValues")]
    pub public_key_values: Option<Vec<serde_json::Value>>,

    #[serde(rename = "X509SKIs")]
    pub x509_skis: Option<Vec<String>>,

    #[serde(rename = "OtherIds")]
    pub other_ids: Option<Vec<String>>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PkiObject {
    pub val: String,
    pub encoding: Option<String>,
    #[serde(rename = "specRef")]
    pub spec_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiLangString {
    pub lang: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiLangUri {
    pub lang: String,
    pub uri_value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemeOperatorAddress {
    #[serde(rename = "SchemeOperatorPostalAddress")]
    pub scheme_operator_postal_address: Vec<PostalAddress>,
    #[serde(rename = "SchemeOperatorElectronicAddress")]
    pub scheme_operator_electronic_address: Vec<MultiLangUri>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicyOrLegalNoticeItem {
    Policy {
        #[serde(rename = "LoTEPolicy")]
        lote_policy: MultiLangUri,
    },
    LegalNotice {
        #[serde(rename = "LoTELegalNotice")]
        lote_legal_notice: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtherLoTEPointer {
    #[serde(rename = "LoTELocation")]
    pub lote_location: String,
    #[serde(rename = "ServiceDigitalIdentities")]
    pub service_digital_identities: Vec<ServiceDigitalIdentity>,
    #[serde(rename = "LoTEQualifiers")]
    pub lote_qualifiers: Vec<LoTEQualifier>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoTEQualifier {
    #[serde(rename = "LoTEType")]
    pub lote_type: String,
    #[serde(rename = "SchemeOperatorName")]
    pub scheme_operator_name: Vec<MultiLangString>,
    #[serde(rename = "MimeType")]
    pub mime_type: String,
    #[serde(rename = "SchemeTypeCommunityRules")]
    pub scheme_type_community_rules: Option<Vec<MultiLangUri>>,
    #[serde(rename = "SchemeTerritory")]
    pub scheme_territory: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSupplyPoint {
    #[serde(rename = "ServiceType")]
    pub service_type: Option<String>,
    #[serde(rename = "uriValue")]
    pub uri_value: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceHistoryInstance {
    #[serde(rename = "ServiceName")]
    pub service_name: Vec<MultiLangString>,
    #[serde(rename = "ServiceDigitalIdentity")]
    pub service_digital_identity: ServiceDigitalIdentity,
    #[serde(rename = "ServiceStatus")]
    pub service_status: String,
    #[serde(rename = "StatusStartingTime")]
    pub status_starting_time: String,
    #[serde(rename = "ServiceTypeIdentifier")]
    pub service_type_identifier: Option<String>,
    #[serde(rename = "ServiceInformationExtensions")]
    pub service_information_extensions: Option<Vec<serde_json::Value>>,
}
