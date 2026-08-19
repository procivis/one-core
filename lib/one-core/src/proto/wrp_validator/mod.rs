use error::WRPValidatorError;
use model::{
    AccessCertificateResult, FetchRegistryResult, RegistrationCertificateResult, TrustScope,
};
use standardized_types::etsi_119_475::registration_certificate::Payload;
use time::Duration;
use url::Url;

use crate::model::claim::Claim;
use crate::model::credential_schema::CredentialSchema;
use crate::provider::credential_formatter::model::{PublicKeySource, X5References};
use crate::provider::trust_list_subscriber::TrustEntityResponse;

pub(crate) mod error;
pub(crate) mod model;
pub(crate) mod validator;

pub(crate) const QUALIFIED_EAA_CATEGORY: &str = "urn:etsi:esi:eaa:eu:qualified";

pub(crate) fn credential_category(claims: &[Claim], namespaced: bool) -> Option<&str> {
    claims
        .iter()
        .find(
            |claim| match claim.path.split_once(crate::mapper::NESTED_CLAIM_MARKER) {
                None => !namespaced && claim.path == "category",
                Some((_namespace, rest)) => namespaced && rest == "category",
            },
        )
        .and_then(|claim| claim.value.as_deref())
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait WRPValidator: Send + Sync {
    /// Validate and optionally resolve WRPAC trust information
    async fn validate_access_certificate<'a>(
        &self,
        pem_chain: &str,
        validate_trust: Option<&'a TrustScope>,
    ) -> Result<AccessCertificateResult, WRPValidatorError>;

    async fn validate_registration_certificate<'a>(
        &self,
        wrprc_jwt: &str,
        expected_relying_party_id: &str,
        validate_trust: Option<&'a TrustScope>,
        leeway: Duration,
    ) -> Result<RegistrationCertificateResult, WRPValidatorError>;

    fn validate_registration_certificates_consistency(
        &self,
        first: &Payload,
        second: &Payload,
    ) -> Result<(), WRPValidatorError>;

    /// Receive registration from the WRP registry
    async fn fetch_from_registry<'a>(
        &self,
        relying_party_id: &str,
        registry_url: &Url,
        validate_trust: Option<&'a TrustScope>,
        leeway: Duration,
    ) -> Result<FetchRegistryResult, WRPValidatorError>;

    async fn validate_credential_issuer<'a>(
        &self,
        issuer_certificate_pem_chain: Option<&'a str>,
        credential_schema: &CredentialSchema,
        credential_category: Option<&'a str>,
        issuer_x5_references: X5References,
        trust_scope: &TrustScope,
    ) -> Result<Option<TrustEntityResponse>, WRPValidatorError>;

    /// Validate that the wallet provider which signed a wallet attestation (WIA/WUA)
    /// is trusted in the given organisation
    async fn validate_wallet_provider<'a>(
        &self,
        key_source: PublicKeySource<'a>,
        trust_scope: &TrustScope,
    ) -> Result<Option<TrustEntityResponse>, WRPValidatorError>;
}
