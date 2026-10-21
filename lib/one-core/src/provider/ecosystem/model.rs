use std::borrow::Cow;

use serde::Serialize;
use shared_types::{
    CredentialId, CredentialSchemaId, ProofId, ProofSchemaId, SerializedCredential,
};
use standardized_types::openid4vci::CredentialIssuerMetadata;
use standardized_types::openid4vp::VerifierInfoAttestation;
use standardized_types::openid4vp::dcql::DcqlQuery;
use strum::Display;
use time::OffsetDateTime;

use crate::model::blob::BlobType;
use crate::model::claim::Claim;
use crate::model::credential::Credential;
use crate::model::credential_schema::WalletAttestation;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::ecosystem::EcosystemTrustResult;
use crate::model::identifier_trust_information::SchemaFormat;
use crate::model::relation::{Related, RelatedVec};
use crate::proto::jwt::model::DecomposedJwt;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::service::common_dto::EudiTrustInformationResponseDTO;
use crate::service::managed_instance::dto::{
    WalletInstanceAttestationClaims, WalletUnitAttestationClaims,
};

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EcosystemCapabilities {
    pub ecosystem_roles: Vec<EcosystemRole>,
}

/// A successful ecosystem check and any data needed by later protocol steps.
pub struct EcosystemValidationResult {
    pub result: EcosystemTrustResult,
    pub data: Option<serde_json::Value>,
}

impl From<EcosystemTrustResult> for EcosystemValidationResult {
    fn from(result: EcosystemTrustResult) -> Self {
        Self { result, data: None }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EcosystemRole {
    Holder,
    Issuer,
    Verifier,
    PidProvider,
    NationalRegistryRegistrar,
    WalletProvider,
}

#[derive(Clone, Debug)]
pub enum IssuerMetadataRepresentation {
    Signed(Box<DecomposedJwt<CredentialIssuerMetadata>>),
    Unsigned(Box<CredentialIssuerMetadata>),
}

#[derive(Clone, Debug, Display)]
#[expect(
    clippy::large_enum_variant,
    reason = "Holder issuance can carry an owned credential"
)]
pub enum ProtocolArtifact<'a> {
    /// As holder, protocol artifacts about the issuance & issuer
    HolderIssuanceInvitation {
        issuer_metadata: IssuerMetadataRepresentation,
        credential_configuration_ids: Vec<String>,
    },
    HolderIssuanceCredential {
        credential: Cow<'a, Credential>,
        serialized: SerializedCredential,
        credential_configuration_id: String,
    },
    /// As holder, protocol artifacts about the proof-request & verifier
    HolderProof {
        verifier_details: Option<IdentifierDetails>,
        dcql_query: DcqlQuery,
        verifier_info: Vec<VerifierInfoAttestation>,
        proof_id: ProofId,
    },
    /// As issuer, issuance protocol artifacts
    IssuerIssuance {
        attestation: WalletAttestationArtifact<'a>,
        /// as defined by the credential schema
        requirements: &'a WalletAttestation,
        credential_id: CredentialId,
    },
    /// As verifier, protocol artifacts of a proof-request (after submission)
    VerifierSubmission {
        credential_id: CredentialId,
        claims: Cow<'a, RelatedVec<Claim>>,
        format: Cow<'a, Related<CredentialSchemaFormat>>,
        issuer_details: Cow<'a, IdentifierDetails>,
        proof_id: ProofId,
    },
}

/// Parsed and signature-checked by the issuance protocol, the token is kept for the status list lookup.
#[derive(Clone, Debug)]
pub enum WalletAttestationArtifact<'a> {
    /// OAuth client attestation at the token endpoint (WIA)
    WalletInstance {
        token: &'a str,
        jwt: &'a DecomposedJwt<WalletInstanceAttestationClaims>,
    },
    /// Key attestation of the holder proof at the credential endpoint (KA)
    Key {
        token: &'a str,
        jwt: &'a DecomposedJwt<WalletUnitAttestationClaims>,
    },
}

#[derive(Clone, Debug, Display)]
pub enum SchemaFilter {
    CredentialSchema(CredentialSchemaId),
    ProofSchema(ProofSchemaId),
}

pub struct TrustDetail {
    pub received_at: OffsetDateTime,
    pub info: TrustDetailInfo,
}

pub enum TrustDetailInfo {
    Eudi(EudiTrustInformationResponseDTO),
}

/// The kind of trust information document uploaded for an identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentifierTrustInformationType {
    RegistrationCertificate,
}

/// A single trust information document, still in its raw (serialized) form.
#[derive(Clone, Debug)]
pub struct TrustInformationInput {
    pub data: String,
    pub r#type: IdentifierTrustInformationType,
}

/// The data extracted from a [`TrustInformationInput`] once an ecosystem has validated it,
/// ready to be persisted alongside the original blob.
#[derive(Clone, Debug)]
pub struct ParsedTrustInformation {
    pub valid_from: Option<OffsetDateTime>,
    pub valid_to: Option<OffsetDateTime>,
    pub intended_use: Option<String>,
    pub allowed_issuance_types: Vec<SchemaFormat>,
    pub allowed_verification_types: Vec<SchemaFormat>,
    pub blob_type: BlobType,
}
