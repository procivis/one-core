use std::collections::HashMap;
use std::sync::Arc;

use one_dto_mapper::convert_inner;
use shared_types::{EcosystemId, OrganisationId, ProofId};
use standardized_types::etsi_119_475::registration_certificate;
use standardized_types::etsi_119_475::registry::IntendedUse;
use standardized_types::etsi_119_602::MultiLangString;
use standardized_types::eudi_ts2::PolicyType;
use standardized_types::openid4vp::VerifierInfoAttestation;
use standardized_types::openid4vp::dcql::{CredentialQuery, CredentialQueryId, DcqlQuery};
use time::Duration;
use url::Url;
use uuid::Uuid;

use super::mapper::credential_query_matches_reg_cert_credential;
use super::{HolderProofError, HolderProofResolver, ProofTrustSource};
use crate::config::core_config::BlobStorageType;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt, NestedError};
use crate::model::blob::{Blob, BlobType};
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
    WalletRelyingPartyMetadata,
};
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::proto::wrp_validator::WRPValidator;
use crate::proto::wrp_validator::model::AccessCertificateResult;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::repository::history_repository::HistoryRepository;

impl HolderProofResolver {
    pub(crate) fn new(
        history_repository: Arc<dyn HistoryRepository>,
        wrp_validator: Arc<dyn WRPValidator>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        session_provider: Arc<dyn SessionProvider>,
        ecosystem: EcosystemId,
    ) -> Self {
        Self {
            history_repository,
            wrp_validator,
            blob_storage_provider,
            session_provider,
            ecosystem,
        }
    }

    #[tracing::instrument(level = "debug", skip_all, err(level = "debug"))]
    pub(crate) async fn resolve_trust(
        &self,
        verifier_details: Option<&IdentifierDetails>,
        proof_id: ProofId,
        organisation_id: OrganisationId,
        dcql_query: &DcqlQuery,
        verifier_info: &[VerifierInfoAttestation],
        leeway: Duration,
    ) -> Result<(), HolderProofError> {
        // trust ecosystem does not support other identifiers than certificates
        let access_certificate = match verifier_details {
            None => {
                return Err(HolderProofError::MissingIdentifier);
            }
            Some(IdentifierDetails::Certificate(access_certificate)) => access_certificate,
            Some(details) => {
                return Err(HolderProofError::InvalidIdentifierType(
                    details.identifier_type(),
                ));
            }
        };

        let access_certificate_trust = self
            .validate_access_certificate(access_certificate, proof_id, organisation_id)
            .await?;

        if verifier_info.is_empty() {
            let registry_url = access_certificate_trust
                .registry_url
                .as_ref()
                .ok_or(HolderProofError::MissingRegistryUrl)?;

            self.validate_against_registry_info(
                &access_certificate_trust.relying_party_id,
                registry_url,
                dcql_query,
                proof_id,
                organisation_id,
                leeway,
            )
            .await?
        } else {
            // check query against registration certificates
            self.validate_registration_certificates(
                verifier_info,
                dcql_query,
                &access_certificate_trust.relying_party_id,
                proof_id,
                organisation_id,
                leeway,
            )
            .await?
        };

        Ok(())
    }

    async fn validate_access_certificate(
        &self,
        certificate: &CertificateDetails,
        proof_id: ProofId,
        organisation_id: OrganisationId,
    ) -> Result<AccessCertificateResult, HolderProofError> {
        let result = self
            .wrp_validator
            .validate_access_certificate(
                &certificate.chain,
                Some(&self.trust_scope(organisation_id)),
            )
            .await
            .error_while("validating access certificate")?;

        self.store_trust_history_event(
            HistoryAction::WrpAcReceived,
            proof_id,
            organisation_id,
            Some(certificate.chain.to_owned()),
            None,
        )
        .await?;

        Ok(result)
    }

    async fn validate_registration_certificates(
        &self,
        verifier_info: &[VerifierInfoAttestation],
        dcql_query: &DcqlQuery,
        expected_rp_id: &str,
        proof_id: ProofId,
        organisation_id: OrganisationId,
        leeway: Duration,
    ) -> Result<(), HolderProofError> {
        #[derive(Clone)]
        struct RefCertCredentialInfo<'a> {
            credential_def: standardized_types::etsi_119_475::Credential,
            reg_cert: &'a VerifierInfoAttestation,
            purpose: Vec<standardized_types::etsi_119_475::MultiLangString>,
            relying_party_name: String,
        }

        let mut allowed_credentials: HashMap<
            Option<CredentialQueryId>,
            Vec<RefCertCredentialInfo>,
        > = HashMap::new();
        let mut last_reg_cert_jwt: Option<registration_certificate::Payload> = None;
        // Individual registration certificate failures are tolerated (a verifier may present
        // several, only one has to match). Keep the first concrete reason so that, if *every*
        // certificate fails, the wallet sees why instead of a generic "query not allowed".
        let mut first_reg_cert_error: Option<NestedError> = None;
        for reg_cert in verifier_info {
            let trusted = match self
                .wrp_validator
                .validate_registration_certificate(
                    &reg_cert.data,
                    expected_rp_id,
                    Some(&self.trust_scope(organisation_id)),
                    leeway,
                )
                .await
            {
                Ok(trusted) => trusted,
                Err(err) => {
                    tracing::warn!(%err, "Provided registration certificate validation failure");
                    first_reg_cert_error.get_or_insert_with(|| {
                        err.error_while("validating registration certificate")
                    });
                    continue;
                }
            };

            if let Some(last_reg_cert) = &last_reg_cert_jwt
                && let Err(err) = self
                    .wrp_validator
                    .validate_registration_certificates_consistency(
                        last_reg_cert,
                        &trusted.payload.custom,
                    )
            {
                tracing::warn!(%err, "validating registration certificates similarity");
                first_reg_cert_error.get_or_insert_with(|| {
                    err.error_while("checking registration certificate consistency")
                });
                continue;
            }
            last_reg_cert_jwt = Some(trusted.payload.custom.clone());

            let (Some(credentials), Some(purpose)) = (
                trusted.payload.custom.credentials,
                trusted.payload.custom.purpose,
            ) else {
                continue;
            };

            let creds_with_reg_cert: Vec<_> = credentials
                .into_iter()
                .map(|credential_def| RefCertCredentialInfo {
                    credential_def,
                    reg_cert,
                    purpose: purpose.to_owned(),
                    relying_party_name: trusted.payload.custom.name.to_owned(),
                })
                .collect();

            if reg_cert.credential_ids.is_empty() {
                allowed_credentials
                    .entry(None)
                    .or_default()
                    .extend(creds_with_reg_cert);
            } else {
                for credential_id in &reg_cert.credential_ids {
                    allowed_credentials
                        .entry(Some(credential_id.to_owned()))
                        .or_default()
                        .extend(creds_with_reg_cert.to_owned());
                }
            }
        }

        // Every provided registration certificate failed validation - report the underlying
        // reason (untrusted provider, AC/RC mismatch, invalid fields, ...) rather than the
        // generic "requested credential not permitted".
        if allowed_credentials.is_empty()
            && let Some(err) = first_reg_cert_error
        {
            return Err(err.into());
        }

        struct RegCertInfo {
            relying_party_name: String,
            purpose: HashMap<CredentialQueryId, Vec<MultiLangString>>,
        }
        let mut used_reg_certs: HashMap<String, RegCertInfo> = HashMap::new();
        for credential_query in &dcql_query.credentials {
            let empty = vec![];
            let mut related_reg_cert_credentials = allowed_credentials
                .get(&None)
                .unwrap_or(&empty)
                .iter()
                .chain(
                    allowed_credentials
                        .get(&Some(credential_query.id.to_owned()))
                        .unwrap_or(&empty),
                );

            let Some(RefCertCredentialInfo {
                reg_cert,
                purpose,
                relying_party_name,
                ..
            }) = related_reg_cert_credentials.find(
                |RefCertCredentialInfo { credential_def, .. }| {
                    credential_query_matches_reg_cert_credential(credential_query, credential_def)
                },
            )
            else {
                return Err(HolderProofError::DisallowedQuery {
                    query: credential_query.id.to_owned(),
                    document: ProofTrustSource::RegistrationCertificate,
                });
            };

            used_reg_certs
                .entry(reg_cert.data.to_owned())
                .or_insert(RegCertInfo {
                    relying_party_name: relying_party_name.to_owned(),
                    purpose: Default::default(),
                })
                .purpose
                .insert(
                    credential_query.id.to_owned(),
                    convert_inner(purpose.to_owned()),
                );
        }

        for (
            used_reg_cert,
            RegCertInfo {
                relying_party_name,
                purpose,
            },
        ) in used_reg_certs
        {
            self.store_trust_history_event(
                HistoryAction::WrpRcReceived,
                proof_id,
                organisation_id,
                Some(used_reg_cert),
                Some(WalletRelyingPartyMetadata {
                    name: Some(relying_party_name),
                    purpose,
                    ..Default::default()
                }),
            )
            .await?;
        }

        Ok(())
    }

    async fn validate_against_registry_info(
        &self,
        relying_party_id: &str,
        registry_url: &Url,
        dcql_query: &DcqlQuery,
        proof_id: ProofId,
        organisation_id: OrganisationId,
        leeway: Duration,
    ) -> Result<(), HolderProofError> {
        let info = self
            .wrp_validator
            .fetch_from_registry(
                relying_party_id,
                registry_url,
                Some(&self.trust_scope(organisation_id)),
                leeway,
            )
            .await
            .error_while("fetching from WRP registry")?;

        let mut purpose: HashMap<CredentialQueryId, Vec<MultiLangString>> = Default::default();
        let mut privacy_policy_url: Option<Url> = None;
        for credential_query in &dcql_query.credentials {
            let Some(matched) = find_matching_intended_use(
                credential_query,
                &info.payload.custom.data.intended_use,
            ) else {
                return Err(HolderProofError::DisallowedQuery {
                    query: credential_query.id.to_owned(),
                    document: ProofTrustSource::NationalRegistry,
                });
            };

            purpose.insert(credential_query.id.to_owned(), matched.purpose);
            if privacy_policy_url.is_none() {
                privacy_policy_url = matched.privacy_policy_url;
            }
        }

        self.store_trust_history_event(
            HistoryAction::WrpNrReceived,
            proof_id,
            organisation_id,
            Some(info.jwt),
            Some(WalletRelyingPartyMetadata {
                name: info.payload.custom.data.trade_name,
                purpose,
                privacy_policy_url,
                ..Default::default()
            }),
        )
        .await?;

        Ok(())
    }

    async fn store_trust_history_event(
        &self,
        action: HistoryAction,
        proof_id: ProofId,
        organisation_id: OrganisationId,
        blob_content: Option<String>,
        metadata: Option<WalletRelyingPartyMetadata>,
    ) -> Result<(), HolderProofError> {
        let metadata_blob_id = if let Some(blob_content) = blob_content {
            let blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)?;

            let blob = Blob::new(blob_content, BlobType::HistoryMetadata);

            let blob_id = blob.id;
            blob_storage
                .create(blob)
                .await
                .error_while("creating history metadata blob")?;

            Some(blob_id)
        } else {
            None
        };

        self.history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                action,
                name: Default::default(),
                target: None,
                source: HistorySource::Core,
                entity_id: Some(proof_id.into()),
                entity_type: HistoryEntityType::Proof,
                metadata: Some(HistoryMetadata::WalletRelyingParty(
                    WalletRelyingPartyMetadata {
                        ecosystem: Some(self.ecosystem.to_owned()),
                        ..metadata.unwrap_or_default()
                    },
                )),
                metadata_blob_id,
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().user(),
            })
            .await
            .error_while("storing history")?;

        Ok(())
    }
}

struct MatchedIntendedUse {
    purpose: Vec<MultiLangString>,
    privacy_policy_url: Option<Url>,
}

fn find_matching_intended_use(
    credential_query: &CredentialQuery,
    among_uses: &[IntendedUse],
) -> Option<MatchedIntendedUse> {
    for intended_use in among_uses {
        if intended_use
            .credential
            .iter()
            .any(|c| credential_query_matches_reg_cert_credential(credential_query, c))
        {
            let privacy_policy_url = intended_use
                .privacy_policy
                .iter()
                .find(|policy| policy.r#type == PolicyType::PrivacyPolicy)
                .map(|policy| policy.policy_uri.to_owned());
            return Some(MatchedIntendedUse {
                purpose: convert_inner(intended_use.purpose.to_owned()),
                privacy_policy_url,
            });
        }
    }
    None
}
