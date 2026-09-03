#![expect(deprecated)]

use one_core::model::identifier::{
    ExactIdentifierFilterColumn, IdentifierState, IdentifierType, SortableIdentifierColumn,
};
use one_core::provider::ecosystem::model::EcosystemRole;
use one_core::provider::trust_list_subscriber::{TrustEntityMetadata, TslServiceEntry};
use one_core::service::certificate::dto::{
    CreateCertificateCaDTO, CreateCertificateContentDTO, CreateCertificateRequestDTO,
};
use one_core::service::error::ServiceError;
use one_core::service::identifier::dto::{
    CertificateRolesMatchMode, CreateCertificateAuthorityRequestDTO, CreateIdentifierDidRequestDTO,
    CreateIdentifierKeyRequestDTO, CreateIdentifierRequestDTO,
    CreateIdentifierTrustInformationRequestDTO, CreateRemoteCertificateChainDTO,
    CreateRemoteIdentifierRequestDTO, CreateSelfSignedCertificateAuthorityContentRequestDTO,
    CreateSelfSignedCertificateAuthorityIssuerAlternativeNameRequest,
    CreateSelfSignedCertificateAuthorityIssuerAlternativeNameType,
    CreateSelfSignedCertificateAuthorityRequestDTO, GetIdentifierListItemResponseDTO,
    GetIdentifierListResponseDTO, GetIdentifierResponseDTO, IdentifierFilterParamsDTO,
    IdentifierTrustInformationResponseDTO, IdentifierTrustInformationType,
    ResolveTrustEntriesRequestDTO, ResolvedTrustEntriesResponseDTO, ResolvedTrustEntryResponseDTO,
    ResolvedTrustEntrySourceResponseDTO,
};
use one_dto_mapper::{
    From, Into, TryFrom, TryInto, convert_inner, convert_inner_of_inner, try_convert_inner,
    try_convert_inner_of_inner,
};
use proc_macros::{ModifySchema, options_not_nullable};
use serde::{Deserialize, Serialize};
use shared_types::{
    CertificateId, CredentialSchemaId, DidMethodId, DidValue, EcosystemId, IdentifierId, KeyId,
    OrganisationId, ProofSchemaId, TrustCollectionId, TrustListSubscriberId,
    TrustListSubscriptionId,
};
use standardized_types::etsi_119_602::TrustedEntityInformation;
use standardized_types::jwk::PublicJwk;
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::{Boolean, ListQueryParamsRest};
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::certificate::dto::{CertificateResponseRestDTO, CertificateRoleRestEnum};
use crate::endpoint::did::dto::{CreateDidRequestKeysRestDTO, DidResponseRestDTO, KeyRoleRestEnum};
use crate::endpoint::key::dto::{
    KeyGenerateCSRRequestProfileRest, KeyGenerateCSRRequestSubjectAlternativeNameRestDTO,
    KeyGenerateCSRRequestSubjectRestDTO, KeyResponseRestDTO,
};
use crate::endpoint::trust_collection::dto::{
    TrustCollectionListItemResponseRestDTO, TrustListRoleRestEnum,
    TrustListSubscriptionStateRestEnum,
};
use crate::mapper::MapperError;
use crate::serialize::{front_time, front_time_option};

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, TryInto)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[try_into(T = CreateIdentifierRequestDTO, Error = ServiceError)]
pub(crate) struct CreateIdentifierRequestRestDTO {
    /// A display name for the identifier.
    #[try_into(infallible)]
    pub name: String,
    /// Create a DID identifier. Provide the DID method and signing
    /// keys.
    #[try_into(with_fn = convert_inner, infallible)]
    pub did: Option<CreateIdentifierDidRequestRestDTO>,
    #[try_into(infallible)]
    /// Deprecated. Use `key` instead.
    #[schema(deprecated = true, nullable = false, value_type = Option<Uuid>)]
    pub key_id: Option<KeyId>,
    /// Create a key identifier.
    #[try_into(with_fn = convert_inner, infallible)]
    pub key: Option<CreateIdentifierKeyRequestRestDTO>,
    /// Create a certificate identifier. Provide an existing certificate
    /// chain, or self-signed configuration and an existing CA identifier
    /// to sign it.
    #[try_into(with_fn = convert_inner_of_inner, infallible)]
    pub certificates: Option<Vec<CreateCertificateRequestRestDTO>>,
    /// Required when not using STS authentication mode. Specifies
    /// organizational context for this operation.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Create a CA identifier. Provide an existing certificate chain
    /// or self-signed CA configuration.
    #[try_into(with_fn = convert_inner_of_inner, infallible)]
    pub certificate_authorities: Option<Vec<CreateCertificateAuthorityRequestRestDTO>>,
    /// Trust information associated with this identifier, establishing
    /// its standing within a particular trust ecosystem.
    #[serde(default)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub trust_information: Vec<CreateIdentifierTrustInformationRequestRestDTO>,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, TryInto)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[try_into(T = CreateRemoteIdentifierRequestDTO, Error = ServiceError)]
pub(crate) struct CreateRemoteIdentifierRequestRestDTO {
    #[try_into(infallible)]
    pub name: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub did: Option<DidValue>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub key: Option<PublicJwk>,
    /// PEM-encoded certificate chains, each from the leaf up to the root.
    #[try_into(with_fn = convert_inner_of_inner, infallible)]
    pub certificates: Option<Vec<CreateRemoteCertificateChainRestDTO>>,
    /// PEM-encoded CA certificate chains.
    #[try_into(with_fn = convert_inner_of_inner, infallible)]
    pub certificate_authorities: Option<Vec<CreateRemoteCertificateChainRestDTO>>,
    /// Required when not using STS authentication mode. Specifies
    /// organizational context for this operation.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
}

#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateRemoteCertificateChainDTO)]
pub(crate) struct CreateRemoteCertificateChainRestDTO {
    /// Full certificate chain in PEM format. Include all certificates
    /// from the leaf up to the root.
    pub chain: String,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateIdentifierTrustInformationRequestDTO)]
pub(crate) struct CreateIdentifierTrustInformationRequestRestDTO {
    /// The trust data payload, formatted according to the specified type.
    pub data: String,
    /// The type of trust information. Determines how `data` is interpreted.
    /// Use `REGISTRATION_CERTIFICATE` to attach a EUDI Registration Certificate
    /// for use with this identifier.
    pub r#type: IdentifierTrustInformationTypeRestEnum,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(IdentifierTrustInformationType)]
#[from(IdentifierTrustInformationType)]
pub(crate) enum IdentifierTrustInformationTypeRestEnum {
    RegistrationCertificate,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Into, ModifySchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateIdentifierDidRequestDTO)]
pub(crate) struct CreateIdentifierDidRequestRestDTO {
    pub name: Option<String>,
    /// Specify the DID method. Check the `did` object of your configuration
    /// for supported options.
    #[modify_schema(field = did)]
    pub method: String,
    pub keys: CreateDidRequestKeysRestDTO,
    pub params: Option<serde_json::Value>,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateCertificateRequestDTO)]
/// Either `chain` or `content` must be specified.
pub(crate) struct CreateCertificateRequestRestDTO {
    /// A display name for the certificate.
    pub name: Option<String>,
    /// The ID of the key the certificate is issued to.
    pub key_id: KeyId,
    /// Full certificate chain in PEM format, where the leaf certificate is
    /// signed by the key specified in keyId. Include all certificates from
    /// the leaf up to the root.
    pub chain: Option<String>,
    /// Configuration to generate a new certificate. Provide subject details
    /// and an existing CA to sign it. Use instead of `chain`.
    #[into(with_fn = convert_inner)]
    pub content: Option<CreateCertificateContentRestDTO>,
    /// Roles assigned to the certificate, controlling how it is used in
    /// credential interactions. Assign `ASSERTION_METHOD` to certificates
    /// used for issuance, and `AUTHENTICATION` to certificates used for
    /// verification or as EU Access Certificates.
    /// Multiple roles may be assigned to a single certificate.
    #[into(with_fn = convert_inner)]
    pub roles: Vec<CertificateRoleRestEnum>,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Into, ModifySchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateCertificateContentDTO)]
pub(crate) struct CreateCertificateContentRestDTO {
    /// The certificate profile to use for generation.
    pub profile: KeyGenerateCSRRequestProfileRest,
    /// Certificate subject details (for example, common name, organization).
    pub subject: KeyGenerateCSRRequestSubjectRestDTO,
    /// Optional Subject Alternative Name (SAN) configuration for the
    /// certificate. Use to specify alternative identifiers such as
    /// DNS names.
    #[into(with_fn = convert_inner)]
    pub subject_alternative_name: Option<KeyGenerateCSRRequestSubjectAlternativeNameRestDTO>,
    /// The CA to sign the new certificate.
    pub certificate_authority: CreateCertificateCaRestDTO,
    /// Signer instance to use for certificate signing. Must reference
    /// an `X509_CERTIFICATE` instance in the `signer` configuration.
    #[modify_schema(field = signer)]
    pub signer: String,
    /// Start of the certificate validity period (RFC 3339). Defaults
    /// to time of issuance.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub validity_start: Option<OffsetDateTime>,
    /// End of the CA certificate validity period (RFC 3339). Must not
    /// exceed the `maxValidityDurationSeconds` set in the referenced `signer`
    /// configuration.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub validity_end: Option<OffsetDateTime>,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateCertificateCaDTO)]
pub(crate) struct CreateCertificateCaRestDTO {
    pub identifier_id: IdentifierId,
    pub certificate_id: Option<CertificateId>,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateIdentifierKeyRequestDTO)]
pub(crate) struct CreateIdentifierKeyRequestRestDTO {
    pub key_id: KeyId,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateCertificateAuthorityRequestDTO)]
pub(crate) struct CreateCertificateAuthorityRequestRestDTO {
    /// The ID of the key used to sign the CA certificate.
    pub key_id: KeyId,
    /// A display name for the CA.
    pub name: Option<String>,
    /// Full certificate chain in PEM format, where the leaf certificate
    /// is a CA certificate signed by the key specified in keyId. The
    /// chain should include all certificates from the leaf CA up to the root.
    pub chain: Option<String>,
    #[into(with_fn = convert_inner)]
    /// Configuration to generate a self-signed root CA. Provide certificate
    /// subject details and validity period. Use instead of `chain`.
    pub self_signed: Option<CreateSelfSignedCertificateAuthorityRequestRestDTO>,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Into, ModifySchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateSelfSignedCertificateAuthorityRequestDTO)]
pub(crate) struct CreateSelfSignedCertificateAuthorityRequestRestDTO {
    /// Certificate subject details for the self-signed CA. For mdoc CAs,
    /// also include an issuer alternative name.
    pub content: CreateSelfSignedCaRequestContentRestDTO,
    /// Signer instance to use for CA certificate signing. Must reference
    /// an `X509_CERTIFICATE` signer configured in the signing configuration.
    /// For mdoc CAs, ensure the referenced instance is configured with
    /// `pathLenConstraint: 0` and `keyIdDerivation: "sha-1"`.
    #[modify_schema(field = signer)]
    pub signer: String,
    /// Start of the CA validity period (RFC 3339). Defaults to time of
    /// issuance.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub validity_start: Option<OffsetDateTime>,
    /// End of the CA validity period (RFC 3339). Must not exceed the
    /// `maxValidityDurationSeconds` set in the referenced `signer`
    /// configuration.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub validity_end: Option<OffsetDateTime>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateSelfSignedCertificateAuthorityContentRequestDTO)]
pub(crate) struct CreateSelfSignedCaRequestContentRestDTO {
    /// Certificate subject details (for example, common name,
    /// organization.)
    pub subject: KeyGenerateCSRRequestSubjectRestDTO,
    /// An alternative name for the CA issuer. Required for mdoc CAs.
    #[into(with_fn = convert_inner)]
    pub issuer_alternative_name: Option<CreateSelfSignedCaRequestIssuerAlternativeNameRestDTO>,
}

#[options_not_nullable]
#[derive(Debug, Clone, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetIdentifierListItemResponseDTO)]
pub(crate) struct GetIdentifierListItemResponseRestDTO {
    pub id: IdentifierId,
    pub name: String,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    pub state: IdentifierStateRest,
    pub r#type: IdentifierTypeRest,
    /// Whether the identifier belongs to the system or comes from an interaction
    /// with an external actor.
    pub is_remote: bool,
    /// Whether the identifier was created automatically by the core rather than
    /// explicitly by the user.
    pub autogenerated: bool,
    pub organisation_id: Option<OrganisationId>,
}

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, TryFrom)]
#[serde(rename_all = "camelCase")]
#[try_from(T = GetIdentifierResponseDTO, Error = MapperError)]
pub(crate) struct GetIdentifierResponseRestDTO {
    #[try_from(infallible)]
    pub id: IdentifierId,
    #[try_from(infallible)]
    pub name: String,
    #[try_from(infallible)]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[try_from(infallible)]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    #[try_from(with_fn = "try_convert_inner")]
    pub did: Option<DidResponseRestDTO>,
    #[try_from(with_fn = "try_convert_inner")]
    pub key: Option<KeyResponseRestDTO>,
    #[try_from(with_fn = "try_convert_inner_of_inner")]
    pub certificates: Option<Vec<CertificateResponseRestDTO>>,
    #[try_from(with_fn = "try_convert_inner_of_inner")]
    pub certificate_authorities: Option<Vec<CertificateResponseRestDTO>>,
    #[try_from(infallible, with_fn = "convert_inner")]
    pub organisation_id: Option<OrganisationId>,
    #[try_from(infallible)]
    pub state: IdentifierStateRest,
    #[try_from(infallible)]
    pub r#type: IdentifierTypeRest,
    #[try_from(infallible)]
    pub is_remote: bool,
    #[try_from(infallible)]
    pub autogenerated: bool,
    #[try_from(infallible, with_fn = "convert_inner")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub trust_information: Vec<IdentifierTrustInformationResponseRestDTO>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(IdentifierState)]
#[into(IdentifierState)]
pub(crate) enum IdentifierStateRest {
    Active,
    Deactivated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(IdentifierType)]
#[into(IdentifierType)]
pub(crate) enum IdentifierTypeRest {
    Did,
    Key,
    Certificate,
    #[serde(rename = "CA")]
    CertificateAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "camelCase")]
#[from(SortableIdentifierColumn)]
#[into(SortableIdentifierColumn)]
pub(crate) enum SortableIdentifierColumnRest {
    Name,
    CreatedDate,
    Type,
    State,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(EcosystemRole)]
pub(crate) enum EcosystemRoleRest {
    Holder,
    Issuer,
    Verifier,
    PidProvider,
    NationalRegistryRegistrar,
    WalletProvider,
}

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, From)]
#[from(IdentifierTrustInformationResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IdentifierTrustInformationResponseRestDTO {
    pub data: String,
    pub r#type: IdentifierTrustInformationTypeRestEnum,
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub valid_from: Option<OffsetDateTime>,
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time_option")]
    pub valid_to: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Deserialize, ToSchema, IntoParams, TryInto)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetIdentifierQuery
#[try_into(T = IdentifierFilterParamsDTO, Error = ServiceError)]
pub(crate) struct IdentifierFilterQueryParamsRestDTO {
    /// Filter by one or more UUIDs.
    #[param(rename = "ids[]", nullable = false)]
    #[try_into(infallible)]
    pub ids: Option<Vec<IdentifierId>>,
    /// Return only identifiers with a name starting with this string.
    /// Not case-sensitive.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub name: Option<String>,
    /// Filter by one or more identifier types.
    #[param(rename = "types[]", nullable = false)]
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    pub types: Option<Vec<IdentifierTypeRest>>,
    /// Filter by one or more identifier states.
    #[param(rename = "states[]", nullable = false)]
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    pub states: Option<Vec<IdentifierStateRest>>,
    /// Filter by one or more DID methods.
    #[param(rename = "didMethods[]", nullable = false)]
    #[try_into(infallible)]
    pub did_methods: Option<Vec<DidMethodId>>,
    /// If true, return only identifiers from interactions with external
    /// actors. If false, return only identifiers local to the system.
    #[param(inline, nullable = false)]
    #[try_into(infallible, with_fn = convert_inner)]
    pub is_remote: Option<Boolean>,
    /// If true, return only identifiers created automatically by the core. If
    /// false, return only identifiers explicitly created by the user.
    #[param(inline, nullable = false)]
    #[try_into(infallible, with_fn = convert_inner)]
    pub autogenerated: Option<Boolean>,
    /// Return keys or DIDs whose keys use the specified algorithm. Check the
    /// `keyAlgorithm` object of the configuration for supported options.
    #[param(rename = "keyAlgorithms[]", nullable = false)]
    #[try_into(infallible)]
    pub key_algorithms: Option<Vec<String>>,
    /// Return keys used as one or more verification methods of a DID.
    #[param(rename = "keyRoles[]", inline, nullable = false)]
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    pub key_roles: Option<Vec<KeyRoleRestEnum>>,
    /// Return keys or DIDs whose keys use the specified storage type. Check the
    /// `keyStorage` object of the configuration for supported options.
    #[param(rename = "keyStorages[]", nullable = false)]
    #[try_into(infallible)]
    pub key_storages: Option<Vec<String>>,

    /// Filter by certificate role. Returns identifiers containing at least
    /// one certificate that matches the specified roles, evaluated according
    /// to `certificateRolesMatchMode`.
    #[param(rename = "certificateRoles[]", nullable = false)]
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    pub certificate_roles: Option<Vec<CertificateRoleRestEnum>>,
    /// Determines how `certificateRoles` is applied at the certificate level.
    /// `ANY` returns identifiers with a certificate holding at least one of
    /// the specified roles. `ALL` returns identifiers with a certificate
    /// holding all of the specified roles.
    #[param(nullable = false)]
    #[try_into(infallible)]
    #[serde(default)]
    pub certificate_roles_match_mode: CertificateRolesMatchModeRestEnum,

    /// Return only identifiers suitable for issuing with the provided
    /// credential schema.
    /// Deprecated: use `ecosystemCredentialSchemaId`
    #[param(nullable = false)]
    #[try_into(infallible)]
    #[deprecated]
    pub trust_issuance_schema_id: Option<CredentialSchemaId>,
    /// Return only identifiers suitable for requesting a proof with the
    /// provided proof schema.
    /// Deprecated: use `ecosystemProofSchemaId`
    #[param(nullable = false)]
    #[try_into(infallible)]
    #[deprecated]
    pub trust_verification_schema_id: Option<ProofSchemaId>,

    #[param(nullable = false)]
    #[try_into(infallible)]
    pub ecosystem: Option<EcosystemId>,
    #[param(rename = "ecosystemRoles[]", inline, nullable = false)]
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    pub ecosystem_roles: Option<Vec<EcosystemRoleRest>>,
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub ecosystem_credential_schema_id: Option<CredentialSchemaId>,
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub ecosystem_proof_schema_id: Option<ProofSchemaId>,

    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    pub exact: Option<Vec<ExactIdentifierFilterColumnRestEnum>>,
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[param(nullable = false)]
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,

    /// Return only identifiers created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only identifiers created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only identifiers last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only identifiers last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(ExactIdentifierFilterColumn)]
pub(crate) enum ExactIdentifierFilterColumnRestEnum {
    Name,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(CertificateRolesMatchMode)]
/// The mode used to match certificate roles. Default any.
pub(crate) enum CertificateRolesMatchModeRestEnum {
    All,
    #[default]
    Any,
}

pub(crate) type GetIdentifierQuery =
    ListQueryParamsRest<IdentifierFilterQueryParamsRestDTO, SortableIdentifierColumnRest>;

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetIdentifierListResponseDTO)]
pub(crate) struct GetIdentifierListResponseRestDTO {
    pub total_pages: u64,
    pub total_items: u64,
    #[from(with_fn = "convert_inner")]
    pub values: Vec<GetIdentifierListItemResponseRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(CreateSelfSignedCertificateAuthorityIssuerAlternativeNameRequest)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateSelfSignedCaRequestIssuerAlternativeNameRestDTO {
    pub r#type: CreateSelfSignedCaRequestIssuerAlternativeNameTypeRest,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[into(CreateSelfSignedCertificateAuthorityIssuerAlternativeNameType)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CreateSelfSignedCaRequestIssuerAlternativeNameTypeRest {
    Email,
    Uri,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(ResolveTrustEntriesRequestDTO)]
pub(crate) struct ResolveTrustEntriesRequestRestDTO {
    pub identifiers: Vec<IdentifierId>,
    #[into(with_fn = "convert_inner_of_inner")]
    pub roles: Option<Vec<TrustListRoleRestEnum>>,
    #[into(with_fn = "convert_inner_of_inner")]
    pub trust_collection_ids: Option<Vec<TrustCollectionId>>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ResolvedTrustEntriesResponseDTO)]
pub(crate) struct ResolvedTrustEntriesResponseRestDTO {
    pub identifier: GetIdentifierListItemResponseRestDTO,
    #[from(with_fn = "convert_inner")]
    pub trust_entries: Vec<ResolvedTrustEntryResponseRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ResolvedTrustEntryResponseDTO)]
pub(crate) struct ResolvedTrustEntryResponseRestDTO {
    #[from(with_fn = "convert_inner")]
    pub metadata: Option<TrustEntityResponseRestEnum>,
    pub source: ResolvedTrustEntrySourceResponseRestDTO,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ResolvedTrustEntrySourceResponseDTO)]
pub(crate) struct ResolvedTrustEntrySourceResponseRestDTO {
    pub id: TrustListSubscriptionId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    #[from(with_fn = convert_inner)]
    pub role: Option<TrustListRoleRestEnum>,
    pub reference: String,
    pub r#type: TrustListSubscriberId,
    pub state: TrustListSubscriptionStateRestEnum,
    pub trust_collection: TrustCollectionListItemResponseRestDTO,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(TslServiceEntry)]
pub(crate) struct TslServiceEntryRestDTO {
    pub service_name: String,
    pub service_type_identifier: String,
    pub service_status: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(TrustEntityMetadata)]
pub(crate) enum TrustEntityResponseRestEnum {
    Lote(TrustedEntityInformation),
    Tsl(TslServiceEntryRestDTO),
}
