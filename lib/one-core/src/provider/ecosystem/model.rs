use std::borrow::Cow;

use serde::Serialize;
use shared_types::{CredentialSchemaId, EcosystemId, ProofId, ProofSchemaId, SerializedCredential};
use standardized_types::openid4vci::CredentialIssuerMetadata;
use standardized_types::openid4vp::VerifierInfoAttestation;
use standardized_types::openid4vp::dcql::DcqlQuery;
use strum::Display;

use crate::model::credential::Credential;
use crate::proto::jwt::model::DecomposedJwt;
use crate::provider::credential_formatter::model::{IdentifierDetails, PublicKeySource};
use crate::service::common_dto::EudiTrustInformationResponseDTO;

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EcosystemCapabilities {
    pub ecosystem_roles: Vec<EcosystemRole>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
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
        verifier_details: Cow<'a, Option<IdentifierDetails>>,
        dcql_query: DcqlQuery,
        verifier_info: Vec<VerifierInfoAttestation>,
        proof_id: ProofId,
    },
    /// As issuer, issuance protocol artifacts
    IssuerIssuance {
        wallet_provider: PublicKeySource<'a>,
    },
    /// As verifier, protocol artifacts of a proof-request (after submission)
    VerifierSubmission {
        credential: Cow<'a, Credential>,
        issuer_details: Cow<'a, IdentifierDetails>,
    },
}

pub enum SchemaFilter {
    CredentialSchema(CredentialSchemaId),
    ProofSchema(ProofSchemaId),
}

pub struct IssuerTrustDetails {
    pub ecosystem: EcosystemId,
    pub issuer: EcosystemTrustDetail,
}

pub struct VerifierTrustDetails {
    pub ecosystem: EcosystemId,
    pub verifier: EcosystemTrustDetail,
}

pub enum EcosystemTrustDetail {
    Eudi(EudiTrustInformationResponseDTO),
}
