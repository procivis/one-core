use std::borrow::Cow;
use std::sync::Arc;

use standardized_types::etsi_119_475::registration_certificate::{Payload, Status};
use standardized_types::jwk::PublicJwk;
use time::Duration;
use url::Url;

use super::error::WRPValidatorError;
use super::model::{
    AccessCertificateResult, FetchRegistryResult, RegistrationCertificateResult, RegistryKeys,
    TrustScope, WRPPayload,
};
use super::{QUALIFIED_EAA_CATEGORY, WRPValidator};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::KeyRole;
use crate::model::list_filter::ListFilterValue;
use crate::model::trust_collection::{TrustCollectionFilterValue, TrustCollectionListQuery};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{
    TrustListSubscription, TrustListSubscriptionFilterValue, TrustListSubscriptionListQuery,
    TrustListSubscriptionState,
};
use crate::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::{DecomposedJwt, JWTPayload};
use crate::proto::key_verification::KeyVerification;
use crate::provider::credential_formatter::model::{
    CertificateDetails, CredentialStatus, IdentifierDetails, PublicKeySource, VerificationFn,
    X5References,
};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::model::RevocationState;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::trust_list_subscriber::TrustEntityResponse;
use crate::provider::trust_list_subscriber::provider::TrustListSubscriberProvider;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use crate::service::error::MissingProviderError;
use crate::util::access_cert_parser::{EtsiParsedAccessCert, etsi_access_cert_from_pem_chain};
use crate::validator::{validate_expiration_time, validate_not_before_time};

pub(crate) struct WRPValidatorImpl {
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    trust_list_subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    client: Arc<dyn HttpClient>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
}

#[async_trait::async_trait]
impl WRPValidator for WRPValidatorImpl {
    async fn validate_access_certificate<'a>(
        &self,
        pem_chain: &str,
        validate_trust: Option<&'a TrustScope>,
    ) -> Result<AccessCertificateResult, WRPValidatorError> {
        let trust_entity = if let Some(trust_scope) = validate_trust {
            Some(
                self.perform_trust_validation(
                    TrustEntityIdentifier::PemChain(Cow::from(pem_chain)),
                    TrustListRoleEnum::WrpAcProvider,
                    trust_scope,
                )
                .await?
                .ok_or(WRPValidatorError::AccessCertificateNotTrusted)?,
            )
        } else {
            None
        };

        let EtsiParsedAccessCert {
            rp_id,
            registry_url,
            ..
        } = etsi_access_cert_from_pem_chain(pem_chain).error_while("parsing access certificate")?;

        Ok(AccessCertificateResult {
            trust_entity,
            relying_party_id: rp_id,
            registry_url,
        })
    }

    async fn validate_registration_certificate<'a>(
        &self,
        wrprc_jwt: &str,
        expected_rp_id: &str,
        validate_trust: Option<&'a TrustScope>,
        leeway: Duration,
    ) -> Result<RegistrationCertificateResult, WRPValidatorError> {
        let token =
            Jwt::<Payload>::build_from_token(wrprc_jwt, Some(&self.verification_fn()), None)
                .await
                .error_while("parsing JWT")?;

        if token
            .payload
            .subject
            .as_ref()
            .is_none_or(|subject| subject != expected_rp_id)
        {
            return Err(WRPValidatorError::InvalidOrganisationIdentifier);
        }

        let issuer = token.header.x5c.ok_or(WRPValidatorError::MissingIssuer)?;
        let issuer_chain = x5c_into_pem_chain(&issuer).error_while("converting chain")?;

        validate_jwt_timestamps(&token.payload, leeway)?;
        self.check_jwt_status(&token.payload.custom.status, &issuer_chain)
            .await?;

        let trust_entity = if let Some(trust_scope) = validate_trust {
            Some(
                self.perform_trust_validation(
                    TrustEntityIdentifier::PemChain(Cow::from(&issuer_chain)),
                    TrustListRoleEnum::WrpRcProvider,
                    trust_scope,
                )
                .await?
                .ok_or(WRPValidatorError::RegistrationCertificateNotTrusted)?,
            )
        } else {
            None
        };

        Ok(RegistrationCertificateResult {
            payload: token.payload,
            trust_entity,
        })
    }

    fn validate_registration_certificates_consistency(
        &self,
        first: &Payload,
        second: &Payload,
    ) -> Result<(), WRPValidatorError> {
        macro_rules! validate_field {
            ($field:ident) => {
                if first.$field != second.$field {
                    tracing::info!(
                        "Registration certificate mismatch field: `{}`: `{:?}` != `{:?}`",
                        stringify!($field),
                        first.$field,
                        second.$field,
                    );
                    return Err(WRPValidatorError::RegistrationCertificateMissmatch {
                        field_name: stringify!($field).to_string(),
                        first_value: format!("{:?}", first.$field),
                        second_value: format!("{:?}", second.$field),
                    });
                }
            };
        }
        validate_field!(name);
        validate_field!(sub_ln);
        validate_field!(sub_gn);
        validate_field!(sub_fn);
        validate_field!(country);
        validate_field!(registry_uri);
        validate_field!(service_descriptions);
        validate_field!(entitlements);
        validate_field!(privacy_policy);
        validate_field!(info_uri);
        validate_field!(supervisory_authority);
        validate_field!(policy_id);
        validate_field!(certificate_policy);
        validate_field!(support_uri);
        validate_field!(intermediary);

        Ok(())
    }

    async fn fetch_from_registry<'a>(
        &self,
        relying_party_id: &str,
        registry_url: &Url,
        validate_trust: Option<&'a TrustScope>,
        leeway: Duration,
    ) -> Result<FetchRegistryResult, WRPValidatorError> {
        let mut rp_url = registry_url.to_owned();
        {
            rp_url
                .path_segments_mut()
                .map_err(|_| WRPValidatorError::InvalidRegistryUrl(registry_url.to_string()))?
                .push("wrp")
                .push(relying_party_id);
        }

        let response = async {
            self.client
                .get(rp_url.as_str())
                .header("Accept", "application/jwt")
                .send()
                .await?
                .error_for_status()
        }
        .await
        .error_while("fetching relying party dataset")?;

        let jku_url = response.header_get("x-jku-url").map(|s| s.to_owned());

        let jwt = String::from_utf8(response.body)?;
        let token = Jwt::<WRPPayload>::decompose_token(&jwt).error_while("parsing JWT")?;
        validate_jwt_timestamps(&token.payload, leeway)?;
        let signing_method = self
            .resolve_signing_method(&token, jku_url.as_deref())
            .await?;
        token
            .verify_signature(signing_method.clone(), &self.verification_fn())
            .await
            .error_while("verifying registry dataset signature")?;

        let trust_entity = if let Some(trust_scope) = validate_trust {
            Some(
                self.perform_trust_validation(
                    signing_method.try_into()?,
                    TrustListRoleEnum::NationalRegistryRegistrar,
                    trust_scope,
                )
                .await?
                .ok_or(WRPValidatorError::RegistryNotTrusted)?,
            )
        } else {
            None
        };

        Ok(FetchRegistryResult {
            payload: token.payload,
            trust_entity,
            jwt,
        })
    }

    async fn validate_credential_issuer<'a>(
        &self,
        issuer_certificate_pem_chain: Option<&'a str>,
        credential_schema: &CredentialSchema,
        pid_schema_ids: &'a [String],
        credential_category: Option<&'a str>,
        issuer_x5_references: X5References,
        trust_scope: &TrustScope,
    ) -> Result<Option<TrustEntityResponse>, WRPValidatorError> {
        if let Some(category) = credential_category {
            if category != QUALIFIED_EAA_CATEGORY {
                return Ok(None);
            }
            return self
                .validate_qeaa_issuer(
                    issuer_certificate_pem_chain,
                    issuer_x5_references,
                    trust_scope,
                )
                .await;
        }

        let credential_schema_schema_id = credential_schema.schema_id().await?;
        if !pid_schema_ids.contains(&credential_schema_schema_id) {
            tracing::debug!("Credential not a PID, skipping issuer trust checks");
            return Ok(None);
        }

        let Some(pem_chain) = issuer_certificate_pem_chain else {
            return Err(WRPValidatorError::IssuerNotTrusted);
        };

        let trusted_entity = self
            .perform_trust_validation(
                TrustEntityIdentifier::PemChain(Cow::from(pem_chain)),
                TrustListRoleEnum::PidProvider,
                trust_scope,
            )
            .await?
            .ok_or(WRPValidatorError::IssuerNotTrusted)?;

        Ok(Some(trusted_entity))
    }

    async fn validate_wallet_provider<'a>(
        &self,
        key_source: PublicKeySource<'a>,
        trust_scope: &TrustScope,
    ) -> Result<Option<TrustEntityResponse>, WRPValidatorError> {
        self.perform_trust_validation(
            key_source.try_into()?,
            TrustListRoleEnum::WalletProvider,
            trust_scope,
        )
        .await
    }
}

enum TrustEntityIdentifier<'a> {
    PemChain(Cow<'a, str>),
    Jwk(Cow<'a, PublicJwk>),
}

impl WRPValidatorImpl {
    async fn validate_qeaa_issuer(
        &self,
        issuer_certificate_pem_chain: Option<&str>,
        issuer_x5_references: X5References,
        trust_scope: &TrustScope,
    ) -> Result<Option<TrustEntityResponse>, WRPValidatorError> {
        let Some(pem_chain) = issuer_certificate_pem_chain else {
            return Err(WRPValidatorError::IssuerNotTrusted);
        };
        // ETSI TS 119 472-1 QEAA-5.6.2-02: the protected header shall carry x5u and
        // x5t#S256. x5c is only recommended (QEAA-5.6.2-03), so it is not required.
        if !(issuer_x5_references.x5u && issuer_x5_references.x5t_s256) {
            tracing::info!("QEAA issuer signature missing required x5u/x5t#S256 references");
            return Err(WRPValidatorError::IssuerNotTrusted);
        }
        let trusted_entity = self
            .perform_trust_validation(
                TrustEntityIdentifier::PemChain(Cow::from(pem_chain)),
                TrustListRoleEnum::QeaaProvider,
                trust_scope,
            )
            .await?
            .ok_or(WRPValidatorError::IssuerNotTrusted)?;
        Ok(Some(trusted_entity))
    }

    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
        trust_list_subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        client: Arc<dyn HttpClient>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    ) -> Self {
        Self {
            trust_collection_repository,
            trust_list_subscription_repository,
            trust_list_subscriber_provider,
            did_method_provider,
            key_algorithm_provider,
            certificate_validator,
            client,
            revocation_method_provider,
        }
    }

    async fn perform_trust_validation(
        &self,
        identifier: TrustEntityIdentifier<'_>,
        role: TrustListRoleEnum,
        trust_scope: &TrustScope,
    ) -> Result<Option<TrustEntityResponse>, WRPValidatorError> {
        let subscriptions = self.get_active_trust_subscriptions(trust_scope).await?;

        self.find_matching_trust_entity(subscriptions, identifier, role)
            .await
    }

    async fn find_matching_trust_entity(
        &self,
        subscriptions: Vec<TrustListSubscription>,
        identifier: TrustEntityIdentifier<'_>,
        requested_role: TrustListRoleEnum,
    ) -> Result<Option<TrustEntityResponse>, WRPValidatorError> {
        for subscription in subscriptions {
            if subscription.role.is_some_and(|role| role != requested_role) {
                continue;
            }

            let subscriber = self
                .trust_list_subscriber_provider
                .get(&subscription.r#type)
                .error_while("getting trust list subscriber")?;

            let reference = subscription.reference.parse()?;
            let trust_entities = match &identifier {
                TrustEntityIdentifier::PemChain(pem_chain) => {
                    subscriber
                        .resolve_certificate(&reference, pem_chain.as_ref())
                        .await
                }
                TrustEntityIdentifier::Jwk(jwk) => {
                    subscriber
                        .resolve_public_key(&reference, jwk.as_ref())
                        .await
                }
            }
            .error_while("resolving trust")?;

            for entity in trust_entities {
                if subscription.role.is_some() || entity.derived_role == Some(requested_role) {
                    return Ok(Some(entity));
                }
            }
        }

        Ok(None)
    }

    async fn get_active_trust_subscriptions(
        &self,
        trust_scope: &TrustScope,
    ) -> Result<Vec<TrustListSubscription>, WRPValidatorError> {
        let collections = self
            .trust_collection_repository
            .list(TrustCollectionListQuery {
                filtering: Some(
                    TrustCollectionFilterValue::OrganisationId {
                        id: trust_scope.organisation_id,
                        include_inherited_collections: true,
                    }
                    .condition()
                        & TrustCollectionFilterValue::Empty(false)
                        & TrustCollectionFilterValue::Ecosystems(vec![
                            trust_scope.ecosystem.to_owned(),
                        ]),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting trust collections")?
            .values
            .into_iter()
            .map(|c| c.id)
            .collect();

        Ok(self
            .trust_list_subscription_repository
            .list(TrustListSubscriptionListQuery {
                filtering: Some(
                    TrustListSubscriptionFilterValue::TrustCollectionId(collections).condition()
                        & TrustListSubscriptionFilterValue::State(vec![
                            TrustListSubscriptionState::Active,
                        ]),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting trust list subscriptions")?
            .values)
    }

    async fn check_jwt_status(
        &self,
        status: &Status,
        issuer_pem_chain: &str,
    ) -> Result<(), WRPValidatorError> {
        const TOKENSTATUSLIST_ENTRY_TYPE: &str = "TokenStatusListEntry";

        let ParsedCertificate {
            attributes,
            subject_common_name,
            ..
        } = self
            .certificate_validator
            .parse_pem_chain(
                issuer_pem_chain,
                CertificateValidationOptions::signature_and_revocation(None),
            )
            .await
            .error_while("parsing issuer certificate")?;

        let (revocation_provider, _) = self
            .revocation_method_provider
            .get_revocation_method_by_status_type(TOKENSTATUSLIST_ENTRY_TYPE)
            .ok_or(
                MissingProviderError::RevocationMethodByCredentialStatusType(
                    TOKENSTATUSLIST_ENTRY_TYPE.to_string(),
                ),
            )
            .error_while("getting revocation provider")?;

        let revocation_status = revocation_provider
            .check_credential_revocation_status(
                &CredentialStatus {
                    id: None,
                    r#type: TOKENSTATUSLIST_ENTRY_TYPE.to_string(),
                    status_purpose: None,
                    additional_fields: status.status_list.to_owned(),
                },
                &IdentifierDetails::Certificate(CertificateDetails {
                    chain: issuer_pem_chain.to_owned(),
                    fingerprint: attributes.fingerprint,
                    expiry: attributes.not_after,
                    subject_common_name,
                    x5_references: Default::default(),
                }),
                None,
                false,
            )
            .await
            .error_while("checking registration certificate status")?;

        match revocation_status {
            RevocationState::Valid => Ok(()),
            RevocationState::Revoked | RevocationState::Suspended { .. } => {
                Err(WRPValidatorError::CertificateRevoked)
            }
        }
    }

    fn verification_fn(&self) -> VerificationFn {
        Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        })
    }

    async fn resolve_signing_method<'a>(
        &self,
        token: &'a DecomposedJwt<WRPPayload>,
        jwks_url: Option<&str>,
    ) -> Result<PublicKeySource<'a>, WRPValidatorError> {
        if let Some(jwks_url) = jwks_url {
            let jwks: RegistryKeys = async {
                self.client
                    .get(jwks_url)
                    .header("Accept", "application/json")
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
            }
            .await
            .error_while("fetching registry keys")?;

            let registry_key = jwks
                .keys
                .into_iter()
                .find(|key| key.kid() == token.header.key_id.as_deref())
                .ok_or(WRPValidatorError::MissingRegistryKey(
                    token.header.key_id.to_owned(),
                ))?;
            return Ok(PublicKeySource::Jwk {
                jwk: Cow::Owned(registry_key),
            });
        };
        if let Some(x5c) = &token.header.x5c {
            return Ok(PublicKeySource::X5c { x5c });
        };
        Err(WRPValidatorError::MissingSigningDetails)
    }
}

fn validate_jwt_timestamps<T>(
    token: &JWTPayload<T>,
    leeway: Duration,
) -> Result<(), WRPValidatorError> {
    validate_not_before_time(&token.invalid_before, leeway).error_while("checking validity")?;
    validate_expiration_time(&token.expires_at, leeway).error_while("checking validity")?;
    Ok(())
}

impl<'a> TryFrom<PublicKeySource<'a>> for TrustEntityIdentifier<'a> {
    type Error = WRPValidatorError;

    fn try_from(value: PublicKeySource<'a>) -> Result<Self, Self::Error> {
        match value {
            PublicKeySource::Did { .. } => {
                Err(WRPValidatorError::InvalidSigningMethod("DID".to_string()))
            }
            PublicKeySource::X5c { x5c } => Ok(Self::PemChain(Cow::from(
                x5c_into_pem_chain(x5c).error_while("converting chain")?,
            ))),
            PublicKeySource::Jwk { jwk } => Ok(Self::Jwk(jwk)),
        }
    }
}

#[cfg(test)]
mod test;
