use std::borrow::Cow;
use std::sync::Arc;

use shared_types::OrganisationId;
use standardized_types::etsi_119_475::registration_certificate::{Payload, Status};
use standardized_types::jwk::PublicJwk;
use time::Duration;
use url::Url;

use super::error::WRPValidatorError;
use super::model::{
    AccessCertificateResult, FetchRegistryResult, RegistrationCertificateResult, RegistryKeys,
    TrustMode, WRPPayload,
};
use super::{QUALIFIED_EAA_CATEGORY, WRPValidator};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::KeyRole;
use crate::model::instance::InstanceRole;
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
use crate::proto::verifier_provider_client::VerifierProviderClient;
use crate::proto::wallet_provider_client::WalletProviderClient;
use crate::provider::credential_formatter::model::{
    CertificateDetails, CredentialStatus, IdentifierDetails, PublicKeySource, VerificationFn,
    X5References,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::model::RevocationState;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::trust_list_subscriber::TrustEntityResponse;
use crate::provider::trust_list_subscriber::provider::TrustListSubscriberProvider;
use crate::repository::instance_repository::InstanceRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use crate::service::error::MissingProviderError;
use crate::util::access_cert_parser::{EtsiParsedAccessCert, etsi_access_cert_from_pem_chain};
use crate::validator::{validate_expiration_time, validate_not_before_time};

pub(crate) struct WRPValidatorImpl {
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    trust_list_subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
    holder_wallet_instance_repository: Arc<dyn InstanceRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    wallet_provider_client: Arc<dyn WalletProviderClient>,
    verifier_provider_client: Arc<dyn VerifierProviderClient>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    client: Arc<dyn HttpClient>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
}

#[async_trait::async_trait]
impl WRPValidator for WRPValidatorImpl {
    async fn validate_access_certificate(
        &self,
        pem_chain: &str,
        validate_trust: Option<OrganisationId>,
    ) -> Result<AccessCertificateResult, WRPValidatorError> {
        let trust_entity = if let Some(organisation_id) = validate_trust {
            Some(
                self.perform_trust_validation(
                    TrustEntityIdentifier::PemChain(Cow::from(pem_chain)),
                    TrustListRoleEnum::WrpAcProvider,
                    organisation_id,
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

    async fn validate_registration_certificate(
        &self,
        wrprc_jwt: &str,
        expected_rp_id: &str,
        validate_trust: Option<OrganisationId>,
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

        let trust_entity = if let Some(organisation_id) = validate_trust {
            Some(
                self.perform_trust_validation(
                    TrustEntityIdentifier::PemChain(Cow::from(&issuer_chain)),
                    TrustListRoleEnum::WrpRcProvider,
                    organisation_id,
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

    async fn fetch_from_registry(
        &self,
        relying_party_id: &str,
        registry_url: &Url,
        validate_trust: Option<OrganisationId>,
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

        let trust_entity = if let Some(organisation_id) = validate_trust {
            Some(
                self.perform_trust_validation(
                    signing_method.try_into()?,
                    TrustListRoleEnum::NationalRegistryRegistrar,
                    organisation_id,
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
        credential_category: Option<&'a str>,
        issuer_x5_references: X5References,
        organisation_id: OrganisationId,
    ) -> Result<Option<TrustEntityResponse>, WRPValidatorError> {
        if let Some(category) = credential_category {
            if category != QUALIFIED_EAA_CATEGORY {
                return Ok(None);
            }
            return self
                .validate_qeaa_issuer(
                    issuer_certificate_pem_chain,
                    issuer_x5_references,
                    organisation_id,
                )
                .await;
        }

        let credential_schema_format = credential_schema.format().await?;
        let formatter_capabilities = self
            .credential_formatter_provider
            .get_credential_formatter(&credential_schema_format)?
            .get_capabilities();

        let credential_schema_schema_id = credential_schema.schema_id().await?;
        if !formatter_capabilities
            .pid_schema_ids
            .contains(&credential_schema_schema_id)
        {
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
                organisation_id,
            )
            .await?
            .ok_or(WRPValidatorError::IssuerNotTrusted)?;

        Ok(Some(trusted_entity))
    }

    async fn validate_wallet_provider<'a>(
        &self,
        key_source: PublicKeySource<'a>,
        organisation_id: OrganisationId,
    ) -> Result<Option<TrustEntityResponse>, WRPValidatorError> {
        self.perform_trust_validation(
            key_source.try_into()?,
            TrustListRoleEnum::WalletProvider,
            organisation_id,
        )
        .await
    }

    async fn wallet_trust_mode(
        &self,
        organisation_id: OrganisationId,
    ) -> Result<TrustMode, WRPValidatorError> {
        let organisation = self
            .organisation_repository
            .get_organisation(&organisation_id)
            .await
            .error_while("getting holder wallet instance")?;

        let enforce_ecosystem_as_holder = organisation.configuration.enforce_ecosystem_as_holder;

        let holder_wallet_instance = self
            .holder_wallet_instance_repository
            .get_by_role(InstanceRole::Wallet, organisation_id)
            .await
            .error_while("getting wallet instance")?;
        if let Some(holder_wallet_instance) = holder_wallet_instance {
            let metadata = self
                .wallet_provider_client
                .get_wallet_provider_metadata(holder_wallet_instance.into())
                .await
                .error_while("getting wallet provider metadata")?;

            if !metadata.feature_flags.ecosystems_enabled {
                // trust management disabled via provider metadata
                return Ok(TrustMode::Disabled);
            }
        }

        Ok(if enforce_ecosystem_as_holder {
            TrustMode::TrustMandatory
        } else {
            TrustMode::TrustOptional
        })
    }

    async fn verifier_trust_mode(
        &self,
        organisation_id: OrganisationId,
    ) -> Result<TrustMode, WRPValidatorError> {
        let organisation = self
            .organisation_repository
            .get_organisation(&organisation_id)
            .await
            .error_while("getting holder wallet instance")?;

        let enforce_ecosystem_as_verifier =
            organisation.configuration.enforce_ecosystem_as_verifier;

        let verifier_instance = self
            .holder_wallet_instance_repository
            .get_by_role(InstanceRole::Verifier, organisation_id)
            .await
            .error_while("getting wallet instance")?;
        if let Some(verifier_instance) = verifier_instance {
            let metadata_url = format!(
                "{}/ssi/verifier-provider/v1/{}",
                verifier_instance.provider_url, verifier_instance.provider_name
            );
            let metadata = self
                .verifier_provider_client
                .get_verifier_provider_metadata(&metadata_url)
                .await
                .error_while("getting verifier provider metadata")?;

            if !metadata.feature_flags.ecosystems_enabled {
                // trust management disabled via provider metadata
                return Ok(TrustMode::Disabled);
            }
        }

        Ok(if enforce_ecosystem_as_verifier {
            TrustMode::TrustMandatory
        } else {
            TrustMode::TrustOptional
        })
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
        organisation_id: OrganisationId,
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
                organisation_id,
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
        holder_wallet_instance_repository: Arc<dyn InstanceRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        wallet_provider_client: Arc<dyn WalletProviderClient>,
        verifier_provider_client: Arc<dyn VerifierProviderClient>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        client: Arc<dyn HttpClient>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    ) -> Self {
        Self {
            trust_collection_repository,
            trust_list_subscription_repository,
            trust_list_subscriber_provider,
            holder_wallet_instance_repository,
            organisation_repository,
            wallet_provider_client,
            verifier_provider_client,
            did_method_provider,
            key_algorithm_provider,
            certificate_validator,
            client,
            revocation_method_provider,
            credential_formatter_provider,
        }
    }

    async fn perform_trust_validation(
        &self,
        identifier: TrustEntityIdentifier<'_>,
        role: TrustListRoleEnum,
        organisation_id: OrganisationId,
    ) -> Result<Option<TrustEntityResponse>, WRPValidatorError> {
        let subscriptions = self.get_active_trust_subscriptions(organisation_id).await?;

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
        organisation_id: OrganisationId,
    ) -> Result<Vec<TrustListSubscription>, WRPValidatorError> {
        let collections = self
            .trust_collection_repository
            .list(TrustCollectionListQuery {
                filtering: Some(
                    TrustCollectionFilterValue::OrganisationId {
                        id: organisation_id,
                        include_inherited_collections: true,
                    }
                    .condition()
                        & TrustCollectionFilterValue::Empty(false),
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
            RevocationState::Revoked
            | RevocationState::Suspended { .. }
            | RevocationState::Expired => Err(WRPValidatorError::CertificateRevoked),
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
mod tests {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::Arc;

    use shared_types::{DidValue, OrganisationId, TrustCollectionId, TrustListSubscriberId};
    use similar_asserts::assert_eq;
    use standardized_types::etsi_119_475::registration_certificate::{
        Payload, Status, SupervisoryAuthority,
    };
    use standardized_types::etsi_119_475::registry::LegalEntity;
    use standardized_types::jwk::{PublicJwk, PublicJwkEc};
    use time::OffsetDateTime;
    use url::Url;

    use super::{QUALIFIED_EAA_CATEGORY, TrustEntityIdentifier, WRPValidatorImpl};
    use crate::model::trust_collection::{GetTrustCollectionList, TrustCollection};
    use crate::model::trust_list_role::TrustListRoleEnum;
    use crate::model::trust_list_subscription::{
        GetTrustListSubscriptionList, TrustListSubscription, TrustListSubscriptionState,
    };
    use crate::proto::certificate_validator::MockCertificateValidator;
    use crate::proto::http_client::{
        HttpClient, Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
    };
    use crate::proto::jwt::model::{DecomposedJwt, JWTHeader, JWTPayload};
    use crate::proto::verifier_provider_client::MockVerifierProviderClient;
    use crate::proto::wallet_provider_client::MockWalletProviderClient;
    use crate::proto::wrp_validator::WRPValidator;
    use crate::proto::wrp_validator::error::WRPValidatorError;
    use crate::proto::wrp_validator::model::{WRPPayload, WRPPayloadData};
    use crate::provider::credential_formatter::model::{PublicKeySource, X5References};
    use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
    use crate::provider::did_method::provider::MockDidMethodProvider;
    use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
    use crate::provider::revocation::provider::MockRevocationMethodProvider;
    use crate::provider::trust_list_subscriber::etsi_lotl::model::TslServiceEntry;
    use crate::provider::trust_list_subscriber::provider::MockTrustListSubscriberProvider;
    use crate::provider::trust_list_subscriber::{
        MockTrustListSubscriber, TrustEntityMetadata, TrustEntityResponse,
    };
    use crate::repository::instance_repository::MockInstanceRepository;
    use crate::repository::organisation_repository::MockOrganisationRepository;
    use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
    use crate::repository::trust_list_subscription_repository::MockTrustListSubscriptionRepository;
    use crate::service::test_utilities::{
        dummy_credential_schema, dummy_organisation, dummy_trust_collection,
    };

    fn make_validator() -> WRPValidatorImpl {
        WRPValidatorImpl::new(
            Arc::new(MockTrustCollectionRepository::default()),
            Arc::new(MockTrustListSubscriptionRepository::default()),
            Arc::new(MockTrustListSubscriberProvider::default()),
            Arc::new(MockInstanceRepository::default()),
            Arc::new(MockOrganisationRepository::default()),
            Arc::new(MockWalletProviderClient::default()),
            Arc::new(MockVerifierProviderClient::default()),
            Arc::new(MockDidMethodProvider::default()),
            Arc::new(MockKeyAlgorithmProvider::default()),
            Arc::new(MockCertificateValidator::default()),
            Arc::new(MockHttpClient::default()),
            Arc::new(MockRevocationMethodProvider::default()),
            Arc::new(MockCredentialFormatterProvider::default()),
        )
    }

    fn make_validator_with_client(client: Arc<dyn HttpClient>) -> WRPValidatorImpl {
        WRPValidatorImpl::new(
            Arc::new(MockTrustCollectionRepository::default()),
            Arc::new(MockTrustListSubscriptionRepository::default()),
            Arc::new(MockTrustListSubscriberProvider::default()),
            Arc::new(MockInstanceRepository::default()),
            Arc::new(MockOrganisationRepository::default()),
            Arc::new(MockWalletProviderClient::default()),
            Arc::new(MockVerifierProviderClient::default()),
            Arc::new(MockDidMethodProvider::default()),
            Arc::new(MockKeyAlgorithmProvider::default()),
            Arc::new(MockCertificateValidator::default()),
            client,
            Arc::new(MockRevocationMethodProvider::default()),
            Arc::new(MockCredentialFormatterProvider::default()),
        )
    }

    fn make_validator_with_subscription(
        subscription: TrustListSubscription,
        resolved_entity: Option<TrustEntityResponse>,
    ) -> WRPValidatorImpl {
        let mut collection_repo = MockTrustCollectionRepository::default();
        collection_repo.expect_list().returning(|_| {
            Ok(GetTrustCollectionList {
                values: vec![TrustCollection {
                    ecosystem: "EUDI".into(),
                    id: TrustCollectionId::from(uuid::Uuid::new_v4()),
                    name: "collection".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    deactivated_at: None,
                    remote_trust_collection_url: None,
                    organisation: dummy_organisation(None).into(),
                }],
                total_pages: 1,
                total_items: 1,
            })
        });

        let mut subscription_repo = MockTrustListSubscriptionRepository::default();
        subscription_repo.expect_list().returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![subscription.clone()],
                total_pages: 1,
                total_items: 1,
            })
        });

        let mut subscriber = MockTrustListSubscriber::default();
        subscriber
            .expect_resolve_certificate()
            .returning(move |_, _| Ok(resolved_entity.clone().into_iter().collect()));

        let subscriber = Arc::new(subscriber);
        let mut subscriber_provider = MockTrustListSubscriberProvider::default();
        subscriber_provider
            .expect_get()
            .returning(move |_| Ok(subscriber.clone()));

        WRPValidatorImpl::new(
            Arc::new(collection_repo),
            Arc::new(subscription_repo),
            Arc::new(subscriber_provider),
            Arc::new(MockInstanceRepository::default()),
            Arc::new(MockOrganisationRepository::default()),
            Arc::new(MockWalletProviderClient::default()),
            Arc::new(MockVerifierProviderClient::default()),
            Arc::new(MockDidMethodProvider::default()),
            Arc::new(MockKeyAlgorithmProvider::default()),
            Arc::new(MockCertificateValidator::default()),
            Arc::new(MockHttpClient::default()),
            Arc::new(MockRevocationMethodProvider::default()),
            Arc::new(MockCredentialFormatterProvider::default()),
        )
    }

    fn dummy_subscription(role: Option<TrustListRoleEnum>) -> TrustListSubscription {
        TrustListSubscription {
            id: uuid::Uuid::new_v4().into(),
            name: "subscription".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deactivated_at: None,
            r#type: TrustListSubscriberId::from_str("ETSI_LOTL").unwrap(),
            reference: "https://example.com/lotl".to_string(),
            role,
            state: TrustListSubscriptionState::Active,
            trust_collection: dummy_trust_collection().into(),
        }
    }

    fn tsl_entity(derived_role: Option<TrustListRoleEnum>) -> TrustEntityResponse {
        TrustEntityResponse {
            derived_role,
            metadata: TrustEntityMetadata::Tsl(TslServiceEntry {
                service_name: "service".to_string(),
                service_type_identifier: "http://example.com/svc".to_string(),
                service_status: "active".to_string(),
            }),
        }
    }

    #[tokio::test]
    async fn test_roleless_subscription_accepts_when_derived_role_matches() {
        // given: a roleless (LOTL) subscription resolving a TSL entry with derived QeaaProvider
        let validator = make_validator_with_subscription(
            dummy_subscription(None),
            Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
        );

        // when: requesting trust for the matching role
        let result = validator
            .perform_trust_validation(
                TrustEntityIdentifier::PemChain(Cow::from("pem")),
                TrustListRoleEnum::QeaaProvider,
                OrganisationId::from(uuid::Uuid::new_v4()),
            )
            .await
            .unwrap();

        // then: the entity is accepted
        assert!(result.is_some(), "expected entity to be accepted");
    }

    #[tokio::test]
    async fn test_roleless_subscription_rejects_when_derived_role_mismatches() {
        // given: a roleless (LOTL) subscription resolving a TSL entry with derived QeaaProvider
        let validator = make_validator_with_subscription(
            dummy_subscription(None),
            Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
        );

        // when: requesting trust for a different role, even though the cert resolves
        let result = validator
            .perform_trust_validation(
                TrustEntityIdentifier::PemChain(Cow::from("pem")),
                TrustListRoleEnum::PidProvider,
                OrganisationId::from(uuid::Uuid::new_v4()),
            )
            .await
            .unwrap();

        // then: the entity is rejected because the derived role does not match
        assert!(result.is_none(), "expected entity to be rejected");
    }

    #[tokio::test]
    async fn test_role_bearing_subscription_accepts_without_derived_role_check() {
        // given: a role-bearing subscription that resolves a TSL entry with a *mismatching*
        // derived role (which must NOT be checked because the subscription was role-filtered)
        let validator = make_validator_with_subscription(
            dummy_subscription(Some(TrustListRoleEnum::PidProvider)),
            Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
        );

        // when
        let result = validator
            .perform_trust_validation(
                TrustEntityIdentifier::PemChain(Cow::from("pem")),
                TrustListRoleEnum::PidProvider,
                OrganisationId::from(uuid::Uuid::new_v4()),
            )
            .await
            .unwrap();

        // then: accepted as-is, no derived-role gate for role-bearing subscriptions
        assert!(
            result.is_some(),
            "expected role-bearing subscription entity to be accepted unchanged"
        );
    }

    fn all_x5_references() -> X5References {
        X5References {
            x5c: true,
            x5u: true,
            x5t_s256: true,
        }
    }

    #[tokio::test]
    async fn test_qeaa_issuer_trusted_when_in_tsl_with_full_x5_references() {
        let validator = make_validator_with_subscription(
            dummy_subscription(None),
            Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
        );

        let result = validator
            .validate_credential_issuer(
                Some("pem"),
                &dummy_credential_schema(),
                Some(QUALIFIED_EAA_CATEGORY),
                all_x5_references(),
                OrganisationId::from(uuid::Uuid::new_v4()),
            )
            .await
            .unwrap();

        assert!(result.is_some(), "QEAA issuer in the TSL must be trusted");
    }

    #[tokio::test]
    async fn test_qeaa_issuer_trusted_without_x5c() {
        let validator = make_validator_with_subscription(
            dummy_subscription(None),
            Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
        );

        // ETSI TS 119 472-1 marks x5c as recommended only; x5u + x5t#S256 suffice.
        let result = validator
            .validate_credential_issuer(
                Some("pem"),
                &dummy_credential_schema(),
                Some(QUALIFIED_EAA_CATEGORY),
                X5References {
                    x5c: false,
                    ..all_x5_references()
                },
                OrganisationId::from(uuid::Uuid::new_v4()),
            )
            .await
            .unwrap();

        assert!(
            result.is_some(),
            "QEAA issuer referencing its certificate via x5u alone must be trusted"
        );
    }

    #[tokio::test]
    async fn test_qeaa_issuer_rejected_when_x5_reference_missing() {
        let validator = make_validator_with_subscription(
            dummy_subscription(None),
            Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
        );

        let result = validator
            .validate_credential_issuer(
                Some("pem"),
                &dummy_credential_schema(),
                Some(QUALIFIED_EAA_CATEGORY),
                X5References {
                    x5u: false,
                    ..all_x5_references()
                },
                OrganisationId::from(uuid::Uuid::new_v4()),
            )
            .await;

        assert!(
            matches!(result, Err(WRPValidatorError::IssuerNotTrusted)),
            "a QEAA issuer missing x5u must be rejected"
        );
    }

    #[tokio::test]
    async fn test_non_qualified_category_skips_issuer_trust_check() {
        let validator = make_validator_with_subscription(
            dummy_subscription(None),
            Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
        );

        let result = validator
            .validate_credential_issuer(
                Some("pem"),
                &dummy_credential_schema(),
                Some("urn:etsi:esi:eaa:eu:pub"),
                all_x5_references(),
                OrganisationId::from(uuid::Uuid::new_v4()),
            )
            .await
            .unwrap();

        assert!(
            result.is_none(),
            "non-qualified EAA is out of scope and must not be trust-checked"
        );
    }

    fn dummy_wrp_payload() -> WRPPayload {
        WRPPayload {
            data: WRPPayloadData {
                trade_name: None,
                support_uri: vec![],
                srv_description: vec![],
                intended_use: vec![],
                is_psb: None,
                entitlement: vec![],
                provides_attestations: vec![],
                supervisory_authority: LegalEntity {
                    legal_person: None,
                    natural_person: None,
                    identifier: vec![],
                    postal_address: None,
                    country: "AT".to_string(),
                    email: vec![],
                    phone: vec![],
                    info_uri: vec![],
                },
                registry_uri: Url::parse("https://registry.example.com").unwrap(),
                uses_intermediary: None,
                legal_person: None,
                natural_person: None,
                identifier: vec![],
                postal_address: None,
                country: "AT".to_string(),
                email: vec![],
                phone: vec![],
                info_uri: vec![],
            },
        }
    }

    fn dummy_decomposed_jwt(
        key_id: Option<String>,
        x5c: Option<Vec<String>>,
    ) -> DecomposedJwt<WRPPayload> {
        DecomposedJwt {
            header: JWTHeader {
                algorithm: "ES256".to_string(),
                key_id,
                r#type: None,
                jwk: None,
                jwt: None,
                key_attestation: None,
                x5c,
                x5u: None,
                x5t_s256: None,
            },
            payload: JWTPayload {
                issued_at: None,
                expires_at: None,
                invalid_before: None,
                issuer: None,
                subject: None,
                audience: None,
                jwt_id: None,
                proof_of_possession_key: None,
                custom: dummy_wrp_payload(),
            },
            signature: vec![],
            unverified_jwt: String::new(),
        }
    }

    fn make_http_response(body: Vec<u8>, url: &str) -> Response {
        Response {
            body,
            headers: Default::default(),
            status: StatusCode(200),
            request: Request {
                body: None,
                headers: Default::default(),
                method: Method::Get,
                url: url.to_owned(),
                timeout: None,
            },
        }
    }

    fn dummy_payload() -> Payload {
        Payload {
            name: "Test RP".to_string(),
            sub_ln: Some("Test Legal Name".to_string()),
            sub_gn: None,
            sub_fn: None,
            country: "AT".to_string(),
            registry_uri: Url::parse("https://registry.example.com").unwrap(),
            service_descriptions: vec![],
            entitlements: vec![],
            privacy_policy: Url::parse("https://example.com/privacy").unwrap(),
            info_uri: Url::parse("https://example.com/info").unwrap(),
            supervisory_authority: SupervisoryAuthority {
                email: "auth@example.com".to_string(),
                phone: "+43123456".to_string(),
                uri: "https://authority.example.com".to_string(),
            },
            policy_id: vec![],
            certificate_policy: Url::parse("https://example.com/policy").unwrap(),
            status: Status {
                status_list: HashMap::new(),
            },
            provides_attestations: None,
            credentials: None,
            purpose: None,
            intended_use_id: None,
            public_body: None,
            support_uri: Url::parse("https://example.com/support").unwrap(),
            intermediary: None,
        }
    }

    #[test]
    fn test_consistency_identical_payloads_returns_ok() {
        // given
        let validator = make_validator();
        let payload = dummy_payload();

        // when
        let result = validator.validate_registration_certificates_consistency(&payload, &payload);

        // then
        assert!(result.is_ok());
    }

    #[test]
    fn test_consistency_name_mismatch_returns_error() {
        // given
        let validator = make_validator();
        let first = dummy_payload();
        let mut second = dummy_payload();
        second.name = "Different RP Name".to_string();

        // when
        let err = validator
            .validate_registration_certificates_consistency(&first, &second)
            .unwrap_err();

        // then
        assert!(
            matches!(
                &err,
                WRPValidatorError::RegistrationCertificateMissmatch { field_name, .. }
                    if field_name == "name"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_consistency_country_mismatch_returns_error() {
        // given
        let validator = make_validator();
        let first = dummy_payload();
        let mut second = dummy_payload();
        second.country = "DE".to_string();

        // when
        let err = validator
            .validate_registration_certificates_consistency(&first, &second)
            .unwrap_err();

        // then
        assert!(
            matches!(
                &err,
                WRPValidatorError::RegistrationCertificateMissmatch { field_name, .. }
                    if field_name == "country"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_consistency_registry_uri_mismatch_returns_error() {
        // given
        let validator = make_validator();
        let first = dummy_payload();
        let mut second = dummy_payload();
        second.registry_uri = Url::parse("https://other-registry.example.com").unwrap();

        // when
        let err = validator
            .validate_registration_certificates_consistency(&first, &second)
            .unwrap_err();

        // then
        assert!(
            matches!(
                &err,
                WRPValidatorError::RegistrationCertificateMissmatch { field_name, .. }
                    if field_name == "registry_uri"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_consistency_support_uri_mismatch_returns_error() {
        // given
        let validator = make_validator();
        let first = dummy_payload();
        let mut second = dummy_payload();
        second.support_uri = Url::parse("https://other-support.example.com").unwrap();

        // when
        let err = validator
            .validate_registration_certificates_consistency(&first, &second)
            .unwrap_err();

        // then
        assert!(
            matches!(
                &err,
                WRPValidatorError::RegistrationCertificateMissmatch { field_name, .. }
                    if field_name == "support_uri"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_consistency_non_validated_fields_are_ignored() {
        // given
        let validator = make_validator();
        let first = dummy_payload();
        let mut second = dummy_payload();
        // `credentials`, `purpose`, `provides_attestations`, and `intended_use_id`
        // are intentionally excluded from the consistency check
        second.credentials = Some(vec![]);
        second.purpose = Some(vec![]);
        second.intended_use_id = Some("different_use_id".to_string());
        second.public_body = Some(true);

        // when
        let result = validator.validate_registration_certificates_consistency(&first, &second);

        // then
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_resolve_signing_method_returns_error_when_no_jwks_url_and_no_x5c() {
        // given
        let validator = make_validator();
        let token = dummy_decomposed_jwt(None, None);

        // when
        let result = validator.resolve_signing_method(&token, None).await;

        // then
        assert!(
            matches!(result, Err(WRPValidatorError::MissingSigningDetails)),
            "unexpected result: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_resolve_signing_method_falls_back_to_x5c_when_no_jwks_url() {
        // given
        let validator = make_validator();
        let x5c = vec!["cert-data".to_string()];
        let token = dummy_decomposed_jwt(None, Some(x5c.clone()));

        // when
        let result = validator
            .resolve_signing_method(&token, None)
            .await
            .unwrap();

        // then
        assert!(
            matches!(result, PublicKeySource::X5c { x5c: refs } if refs == x5c.as_slice()),
            "expected X5c signing method"
        );
    }

    #[tokio::test]
    async fn test_resolve_signing_method_fetches_jwks_and_returns_matching_key() {
        // given
        const JWKS_URL: &str = "https://jwks.example.com/keys";
        const KEY_ID: &str = "test-key-id";

        let mut mock_client = MockHttpClient::new();
        mock_client
            .expect_get()
            .withf(|url| url == JWKS_URL)
            .returning(|url| {
                let mut inner = MockHttpClient::new();
                let body = serde_json::json!({
                    "keys": [{"kty": "EC", "crv": "P-256", "x": "AAAA", "kid": "test-key-id"}]
                })
                .to_string()
                .into_bytes();
                inner
                    .expect_send()
                    .returning(move |url, _, _, _, _| Ok(make_http_response(body.clone(), url)));
                RequestBuilder::new(Arc::new(inner), Method::Get, url)
            });

        let validator = make_validator_with_client(Arc::new(mock_client));
        let token = dummy_decomposed_jwt(Some(KEY_ID.to_string()), None);

        // when
        let result = validator
            .resolve_signing_method(&token, Some(JWKS_URL))
            .await
            .unwrap();

        // then
        let PublicKeySource::Jwk { jwk } = result else {
            panic!("expected Jwk signing method, got something else");
        };
        assert_eq!(jwk.kid(), Some(KEY_ID));
    }

    #[tokio::test]
    async fn test_resolve_signing_method_returns_error_when_key_not_found_in_jwks() {
        // given
        const JWKS_URL: &str = "https://jwks.example.com/keys";

        let mut mock_client = MockHttpClient::new();
        mock_client
            .expect_get()
            .withf(|url| url == JWKS_URL)
            .returning(|url| {
                let mut inner = MockHttpClient::new();
                let body = serde_json::json!({
                    "keys": [{"kty": "EC", "crv": "P-256", "x": "AAAA", "kid": "other-key-id"}]
                })
                .to_string()
                .into_bytes();
                inner
                    .expect_send()
                    .returning(move |url, _, _, _, _| Ok(make_http_response(body.clone(), url)));
                RequestBuilder::new(Arc::new(inner), Method::Get, url)
            });

        let validator = make_validator_with_client(Arc::new(mock_client));
        let token = dummy_decomposed_jwt(Some("requested-key-id".to_string()), None);

        // when
        let result = validator
            .resolve_signing_method(&token, Some(JWKS_URL))
            .await;

        // then
        assert!(
            matches!(
                result,
                Err(WRPValidatorError::MissingRegistryKey(Some(ref kid))) if kid == "requested-key-id"
            ),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_try_from_did_public_key_source_returns_invalid_signing_method() {
        // given
        let did = DidValue::try_from("did:example:123".to_string()).unwrap();
        let source: PublicKeySource<'_> = PublicKeySource::Did {
            did: Cow::Owned(did),
            key_id: None,
        };

        // when
        let result: Result<TrustEntityIdentifier<'_>, WRPValidatorError> = source.try_into();

        // then
        assert!(
            matches!(
                result,
                Err(WRPValidatorError::InvalidSigningMethod(ref method)) if method == "DID"
            ),
            "expected InvalidSigningMethod(DID)"
        );
    }

    #[test]
    fn test_try_from_jwk_public_key_source_returns_jwk_identifier() {
        // given
        let jwk = PublicJwk::Ec(PublicJwkEc {
            alg: None,
            r#use: None,
            kid: Some("key-1".to_string()),
            crv: "P-256".to_string(),
            x: "AAAA".to_string(),
            y: None,
        });
        let source: PublicKeySource<'_> = PublicKeySource::Jwk {
            jwk: Cow::Owned(jwk),
        };

        // when
        let result: Result<TrustEntityIdentifier<'_>, WRPValidatorError> = source.try_into();

        // then
        assert!(
            matches!(result, Ok(TrustEntityIdentifier::Jwk(_))),
            "expected TrustEntityIdentifier::Jwk"
        );
    }
}
