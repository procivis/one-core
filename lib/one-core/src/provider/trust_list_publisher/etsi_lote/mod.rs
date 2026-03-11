pub(crate) mod dto;
mod mapper;

use std::sync::Arc;

use ct_codecs::{Base64, Base64UrlSafeNoPadding, Decoder as _, Encoder as _};
use serde::Deserialize;
use serde_with::DurationSeconds;
use sha2::{Digest, Sha256};
use shared_types::{TrustEntryId, TrustListPublicationId, TrustListPublisherId};
use standardized_types::etsi_119_602::{
    ListAndSchemeInformation, LoTEPayload, LoTEType, MultiLangString, MultiLangUri, PkiObject,
    ServiceDigitalIdentity, ServiceInformation, TrustedEntity, TrustedEntityInformation,
    TrustedEntityService,
};
use standardized_types::jades::JadesHeader;
use time::OffsetDateTime;

use crate::config::core_config::{IdentifierType, KeyAlgorithmType};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::pem_chain_into_x5c;
use crate::model::certificate::CertificateRelations;
use crate::model::identifier::{Identifier, IdentifierRelations};
use crate::model::key::KeyRelations;
use crate::model::trust_entry::{TrustEntry, TrustEntryStatusEnum, UpdateTrustEntryRequest};
use crate::model::trust_list_publication::{
    TrustListPublication, TrustListPublicationRelations, TrustListPublicationRoleEnum,
    UpdateTrustListPublicationRequest,
};
use crate::proto::certificate_validator::parse::extract_leaf_pem_from_chain;
use crate::proto::clock::Clock;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::trust_list_publisher::error::TrustListPublisherError;
use crate::provider::trust_list_publisher::{
    CreateTrustListRequest, TrustListPublisher, TrustListPublisherCapabilities,
};
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::trust_entry_repository::TrustEntryRepository;
use crate::repository::trust_list_publication_repository::TrustListPublicationRepository;
use crate::util::key_selection::{KeySelection, SelectedKey};

pub(crate) struct EtsiLotePublisher {
    pub method_id: TrustListPublisherId,
    pub params: EtsiLoteParams,
    pub clock: Arc<dyn Clock>,
    pub key_provider: Arc<dyn KeyProvider>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    pub trust_list_publication_repository: Arc<dyn TrustListPublicationRepository>,
    pub trust_entry_repository: Arc<dyn TrustEntryRepository>,
    pub identifier_repository: Arc<dyn IdentifierRepository>,
}

#[serde_with::serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EtsiLoteParams {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub refresh_interval_seconds: time::Duration,
}

#[async_trait::async_trait]
impl TrustListPublisher for EtsiLotePublisher {
    fn get_capabilities(&self) -> TrustListPublisherCapabilities {
        TrustListPublisherCapabilities {
            key_algorithms: vec![KeyAlgorithmType::Ecdsa, KeyAlgorithmType::Eddsa],
            publisher_identifier_types: vec![
                IdentifierType::CertificateAuthority,
                IdentifierType::Certificate,
            ],
            entry_identifier_types: vec![
                IdentifierType::Certificate,
                IdentifierType::CertificateAuthority,
            ],
            supported_roles: vec![
                TrustListPublicationRoleEnum::PidProvider,
                TrustListPublicationRoleEnum::WalletProvider,
                TrustListPublicationRoleEnum::WrpAcProvider,
                TrustListPublicationRoleEnum::WrpRcProvider,
                TrustListPublicationRoleEnum::PubEeaProvider,
                TrustListPublicationRoleEnum::NationalRegistryRegistrar,
            ],
        }
    }

    async fn create_trust_list(
        &self,
        request: CreateTrustListRequest,
    ) -> Result<TrustListPublicationId, TrustListPublisherError> {
        let list_params = request
            .params
            .map(dto::CreateTrustListParams::try_from)
            .transpose()?
            .unwrap_or_default();

        let metadata = serde_json::to_vec(&list_params)?;

        let selected = request
            .identifier
            .select_key(KeySelection {
                key: request.key_id,
                certificate: request.certificate_id,
                ..Default::default()
            })
            .error_while("selecting key")?;

        let SelectedKey::Certificate { certificate, key } = &selected else {
            return Err(TrustListPublisherError::InvalidIdentifier(
                "identifier must resolve to a certificate".into(),
            ));
        };

        let publication_id = TrustListPublicationId::from(uuid::Uuid::new_v4());
        let publication = TrustListPublication {
            id: publication_id,
            created_date: self.clock.now_utc(),
            last_modified: self.clock.now_utc(),
            name: request.name,
            role: request.role,
            r#type: self.method_id.clone(),
            metadata,
            deleted_at: None,
            content: None,
            sequence_number: 0,
            organisation_id: request.organisation_id,
            identifier_id: Some(request.identifier.id),
            key_id: Some(key.id),
            certificate_id: Some(certificate.id),
            organisation: None,
            identifier: None,
            key: None,
            certificate: None,
        };

        self.trust_list_publication_repository
            .create(publication)
            .await
            .error_while("creating trust list publication")?;

        self.sign_trust_list(publication_id).await?;

        Ok(publication_id)
    }

    async fn add_entry(
        &self,
        publication: TrustListPublication,
        identifier: Identifier,
        params: Option<serde_json::Value>,
    ) -> Result<TrustEntryId, TrustListPublisherError> {
        let entry_params = params
            .map(dto::AddEntryParams::try_from)
            .transpose()?
            .unwrap_or_default();
        let metadata = serde_json::to_vec(&entry_params)?;

        let entry_id = TrustEntryId::from(uuid::Uuid::new_v4());
        let entry = TrustEntry {
            id: entry_id,
            created_date: self.clock.now_utc(),
            last_modified: self.clock.now_utc(),
            status: TrustEntryStatusEnum::Active,
            metadata,
            trust_list_publication_id: publication.id,
            identifier_id: identifier.id,
            trust_list_publication: None,
            identifier: None,
        };

        self.trust_entry_repository
            .create(entry)
            .await
            .error_while("creating trust entry")?;

        self.sign_trust_list(publication.id).await?;

        Ok(entry_id)
    }

    async fn update_entry(
        &self,
        entry: TrustEntry,
        state: Option<TrustEntryStatusEnum>,
        params: Option<serde_json::Value>,
    ) -> Result<(), TrustListPublisherError> {
        if state.is_none() && params.is_none() {
            return Ok(());
        }

        let metadata = params
            .map(dto::AddEntryParams::try_from)
            .transpose()?
            .map(|p| serde_json::to_vec(&p))
            .transpose()?;

        self.trust_entry_repository
            .update(
                entry.id,
                UpdateTrustEntryRequest {
                    status: state,
                    metadata,
                },
            )
            .await
            .error_while("updating trust entry")?;

        self.sign_trust_list(entry.trust_list_publication_id)
            .await?;
        Ok(())
    }

    async fn remove_entry(&self, entry: TrustEntry) -> Result<(), TrustListPublisherError> {
        self.trust_entry_repository
            .delete(entry.id)
            .await
            .error_while("deleting trust entry")?;

        self.sign_trust_list(entry.trust_list_publication_id)
            .await?;
        Ok(())
    }

    async fn generate_trust_list_content(
        &self,
        publication: TrustListPublication,
    ) -> Result<String, TrustListPublisherError> {
        let refresh_interval = self.params.refresh_interval_seconds;

        if publication.last_modified + refresh_interval > self.clock.now_utc() {
            let content = publication.content.ok_or_else(|| {
                TrustListPublisherError::MissingRelation(
                    "publication missing trust list content".to_string(),
                )
            })?;
            return Ok(String::from_utf8(content)?);
        }

        let content = self.sign_trust_list(publication.id).await?;
        Ok(String::from_utf8(content)?)
    }
}

impl EtsiLotePublisher {
    async fn format_trust_list(
        &self,
        publication: &TrustListPublication,
        organisation_name: &str,
        entries: &[(TrustEntry, Identifier)],
    ) -> Result<Vec<u8>, TrustListPublisherError> {
        let now = self.clock.now_utc();
        let payload = build_lote_payload(
            publication,
            organisation_name,
            entries,
            self.params.refresh_interval_seconds,
            now,
        )?;

        let payload_json = serde_json::to_vec(&payload)?;

        let key = publication.key.as_ref().ok_or_else(|| {
            TrustListPublisherError::MissingRelation("publication missing key".to_string())
        })?;

        let certificate = publication.certificate.as_ref().ok_or_else(|| {
            TrustListPublisherError::MissingRelation("publication missing certificate".to_string())
        })?;

        let x5c = pem_chain_into_x5c(&certificate.chain)?;

        let signer = self
            .key_provider
            .get_signature_provider(key, None, self.key_algorithm_provider.clone())
            .error_while("getting signature provider")?;

        sign_jades_compact(&payload_json, &*signer, x5c, self.clock.now_utc()).await
    }

    async fn sign_trust_list(
        &self,
        publication_id: TrustListPublicationId,
    ) -> Result<Vec<u8>, TrustListPublisherError> {
        let relations = TrustListPublicationRelations {
            organisation: Some(Default::default()),
            key: Some(KeyRelations::default()),
            certificate: Some(CertificateRelations::default()),
            ..Default::default()
        };

        let publication = self
            .trust_list_publication_repository
            .get(publication_id, &relations)
            .await
            .error_while("fetching trust list publication")?
            .ok_or_else(|| {
                TrustListPublisherError::PublicationNotFound(format!(
                    "publication {publication_id} not found"
                ))
            })?;

        let organisation_name = publication
            .organisation
            .as_ref()
            .ok_or_else(|| {
                TrustListPublisherError::MissingRelation(
                    "publication missing organisation".to_string(),
                )
            })?
            .name
            .clone();

        let entry_list = self
            .trust_entry_repository
            .list(publication_id, Default::default())
            .await
            .error_while("listing trust entries")?;

        let identifier_relations = IdentifierRelations {
            certificates: Some(CertificateRelations::default()),
            ..Default::default()
        };

        let mut entries_with_identifiers = Vec::new();
        for entry in entry_list.values {
            let identifier = self
                .identifier_repository
                .get(entry.identifier_id, &identifier_relations)
                .await
                .error_while("fetching entry identifier")?
                .ok_or_else(|| {
                    TrustListPublisherError::MissingRelation(format!(
                        "identifier {} not found for entry {}",
                        entry.identifier_id, entry.id
                    ))
                })?;

            entries_with_identifiers.push((entry, identifier));
        }

        let new_sequence = publication.sequence_number + 1;

        let mut publication_for_build = publication;
        publication_for_build.sequence_number = new_sequence;

        let content = self
            .format_trust_list(
                &publication_for_build,
                &organisation_name,
                &entries_with_identifiers,
            )
            .await?;

        self.trust_list_publication_repository
            .update(
                publication_id,
                UpdateTrustListPublicationRequest {
                    content: Some(Some(content.clone())),
                    sequence_number: Some(new_sequence),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating trust list publication")?;

        Ok(content)
    }
}

fn build_trusted_entity(
    lote_type: &LoTEType,
    identifier: &Identifier,
    params: &dto::AddEntryParams,
) -> Result<TrustedEntity, TrustListPublisherError> {
    let Some(identifier_certificates) = &identifier.certificates else {
        return Err(TrustListPublisherError::InvalidIdentifier(
            "trust entry identifier missing certificates".to_string(),
        ))?;
    };

    let mut pki_objects = Vec::new();
    for cert in identifier_certificates {
        let leaf = extract_leaf_pem_from_chain(cert.chain.as_bytes())
            .error_while("extracting leaf certificate")?;
        let val = Base64::encode_to_string(leaf.contents)?;
        pki_objects.push(PkiObject {
            val,
            ..Default::default()
        });
    }

    let services = lote_type
        .service_type_identifiers()
        .into_iter()
        .map(|(uri, display_name)| TrustedEntityService {
            service_information: ServiceInformation {
                service_type_identifier: uri.to_string(),
                service_name: params.service.name.clone().unwrap_or_else(|| {
                    vec![MultiLangString {
                        lang: "en".into(),
                        value: display_name.to_string(),
                    }]
                }),
                service_digital_identity: Some(ServiceDigitalIdentity {
                    x509_certificates: Some(pki_objects.clone()),
                    ..Default::default()
                }),
                service_supply_points: params.service.supply_points.clone(),
                service_definition_uri: params.service.definition_uri.clone(),
                scheme_service_definition_uri: params.service.scheme_definition_uri.clone(),
                service_information_extensions: params.service.extensions.clone(),
                ..Default::default()
            },
            ..Default::default()
        })
        .collect();

    Ok(TrustedEntity {
        trusted_entity_information: TrustedEntityInformation {
            te_name: params.entity.name.clone().unwrap_or_else(|| {
                vec![MultiLangString {
                    lang: "en".into(),
                    value: identifier.name.clone(),
                }]
            }),
            te_information_uri: params.entity.information_uri.clone(),
            te_address: params.entity.address.clone(),
            te_trade_name: params.entity.trade_name.clone(),
            te_information_extensions: params.entity.extensions.clone(),
        },
        trusted_entity_services: services,
    })
}

fn build_lote_payload(
    publication: &TrustListPublication,
    organisation_name: &str,
    entries: &[(TrustEntry, Identifier)],
    refresh_interval: time::Duration,
    now: OffsetDateTime,
) -> Result<LoTEPayload, TrustListPublisherError> {
    let lote_type = LoTEType::try_from(&publication.role)?;
    let list_params: dto::CreateTrustListParams = serde_json::from_slice(&publication.metadata)?;

    let sequence_number = publication.sequence_number as u64;

    let scheme_info = ListAndSchemeInformation {
        lote_version_identifier: 1,
        lote_sequence_number: sequence_number,
        lote_type: lote_type.to_string(),
        scheme_operator_name: list_params.scheme_operator_name.unwrap_or_else(|| {
            vec![MultiLangString {
                lang: "en".into(),
                value: organisation_name.to_owned(),
            }]
        }),
        scheme_information_uri: list_params.scheme_information_uri,
        status_determination_approach: lote_type.status_determination_approach().to_string(),
        scheme_type_community_rules: Some(vec![MultiLangUri {
            lang: "en".into(),
            uri_value: lote_type.scheme_type_community_rules().to_string(),
        }]),
        scheme_territory: list_params
            .scheme_territory
            .unwrap_or_else(|| lote_type.scheme_territory().to_string()),
        scheme_operator_address: list_params.scheme_operator_address,
        scheme_name: list_params.scheme_name.or_else(|| {
            Some(vec![MultiLangString {
                lang: "en".into(),
                value: publication.name.clone(),
            }])
        }),
        policy_or_legal_notice: list_params.policy_or_legal_notice,
        historical_information_period: list_params.historical_information_period,
        pointers_to_other_lote: list_params.pointers_to_other_lote,
        distribution_points: list_params.distribution_points,
        scheme_extensions: list_params.scheme_extensions,
        list_issue_date_time: format_iso8601(now)?,
        next_update: format_iso8601(now + refresh_interval)?,
    };

    let trusted_entities: Vec<TrustedEntity> = entries
        .iter()
        .map(|(entry, identifier)| {
            let entry_params: dto::AddEntryParams = serde_json::from_slice(&entry.metadata)?;
            build_trusted_entity(&lote_type, identifier, &entry_params)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(LoTEPayload {
        list_and_scheme_information: scheme_info,
        trusted_entities_list: (!trusted_entities.is_empty()).then_some(trusted_entities),
    })
}

fn format_iso8601(dt: OffsetDateTime) -> Result<String, TrustListPublisherError> {
    let format = time::format_description::well_known::Rfc3339;
    Ok(dt.format(&format)?)
}

/// Produce a JAdES Baseline B-B compact JWS (ETSI TS 119 182-1 V1.2.1).
async fn sign_jades_compact(
    payload: &[u8],
    signer: &dyn crate::provider::credential_formatter::model::SignatureProvider,
    x5c: Vec<String>,
    now: OffsetDateTime,
) -> Result<Vec<u8>, TrustListPublisherError> {
    let algorithm = signer.jose_alg().ok_or_else(|| {
        TrustListPublisherError::Signing("no JOSE algorithm for signer key".into())
    })?;

    let x5t_s256 = compute_x5t_s256(x5c.first().ok_or_else(|| {
        TrustListPublisherError::InvalidJws("x5c certificate chain is empty".into())
    })?)?;

    let header = JadesHeader {
        alg: algorithm,
        typ: "JOSE".to_string(),
        crit: vec![],
        iat: now.unix_timestamp(),
        x5c,
        x5t_s256: Some(x5t_s256),
    };

    let header_json = serde_json::to_vec(&header)?;
    let header_b64 = Base64UrlSafeNoPadding::encode_to_string(&header_json)?;
    let payload_b64 = Base64UrlSafeNoPadding::encode_to_string(payload)?;
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signature = signer
        .sign(signing_input.as_bytes())
        .await
        .map_err(|e| TrustListPublisherError::Signing(e.to_string()))?;

    let signature_b64 = Base64UrlSafeNoPadding::encode_to_string(&signature)?;

    Ok(format!("{signing_input}.{signature_b64}").into_bytes())
}

fn compute_x5t_s256(cert_b64: &str) -> Result<String, TrustListPublisherError> {
    let der_bytes = Base64::decode_to_vec(cert_b64, None)?;
    let hash = Sha256::digest(&der_bytes);
    Base64UrlSafeNoPadding::encode_to_string(hash).map_err(Into::into)
}

#[cfg(test)]
mod test;
