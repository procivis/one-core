use std::collections::HashMap;

use ct_codecs::{Base64, Encoder};
use serde::Deserialize;
use serde_with::DurationSeconds;
use shared_types::IdentifierId;
use standardized_types::etsi_119_602::TrustedEntityInformation;
use strum::Display;
use url::Url;
use x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER;

use crate::error::ContextWithErrorCode;
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::key::Key;
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::proto::certificate_validator::parse::extract_leaf_pem_from_chain;
use crate::provider::caching_loader::etsi_lote::EtsiLoteCache;
use crate::provider::trust_list_subscriber::error::TrustListSubscriberError;
use crate::provider::trust_list_subscriber::etsi_lote::model::PreprocessedLote;
use crate::provider::trust_list_subscriber::{
    TrustEntityResponse, TrustListSubscriber, TrustListSubscriberCapabilities,
    TrustListValidationSuccess,
};

mod model;
mod preprocessing;
pub mod resolver;

#[cfg(test)]
mod test;

#[serde_with::serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EtsiLoteParams {
    pub accepts: LoteContentType,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub leeway: time::Duration,
}

#[derive(Clone, Debug, Display, Deserialize)]
pub enum LoteContentType {
    #[strum(to_string = "application/xml")]
    #[serde(rename = "application/xml")]
    Xml,
    #[strum(to_string = "application/jwt")]
    #[serde(rename = "application/jwt")]
    Jwt,
}

pub struct EtsiLoteSubscriber {
    cache: EtsiLoteCache,
}

impl EtsiLoteSubscriber {
    pub fn new(cache: EtsiLoteCache) -> Self {
        Self { cache }
    }

    async fn get_list(
        &self,
        reference: &Url,
    ) -> Result<PreprocessedLote, TrustListSubscriberError> {
        let raw_data = self
            .cache
            .get(reference.as_str())
            .await
            .error_while("getting LOTE from cache")?;
        let list = serde_json::from_slice::<PreprocessedLote>(&raw_data)?;
        Ok(list)
    }
}

#[async_trait::async_trait]
impl TrustListSubscriber for EtsiLoteSubscriber {
    fn get_capabilities(&self) -> TrustListSubscriberCapabilities {
        TrustListSubscriberCapabilities {
            roles: vec![
                TrustListRoleEnum::PidProvider,
                TrustListRoleEnum::WalletProvider,
                TrustListRoleEnum::WrpAcProvider,
                TrustListRoleEnum::PubEeaProvider,
                TrustListRoleEnum::WrpRcProvider,
                TrustListRoleEnum::NationalRegistryRegistrar,
            ],
        }
    }

    async fn validate_subscription(
        &self,
        reference: &Url,
        role: Option<TrustListRoleEnum>,
    ) -> Result<TrustListValidationSuccess, TrustListSubscriberError> {
        let list = self.get_list(reference).await?;
        let role = list
            .role
            .or(role)
            .ok_or(TrustListSubscriberError::UnknownTrustListRole)?;
        Ok(TrustListValidationSuccess { role })
    }

    async fn resolve_entries(
        &self,
        reference: &Url,
        identifiers: &[Identifier],
    ) -> Result<HashMap<IdentifierId, TrustEntityResponse>, TrustListSubscriberError> {
        let list = self.get_list(reference).await?;
        let mut result = HashMap::new();
        for identifier in identifiers {
            if let Some(entity) = find_matching_trusted_entity(identifier, &list)? {
                result.insert(identifier.id, TrustEntityResponse::LOTE(entity));
            }
        }
        Ok(result)
    }
}

fn find_matching_trusted_entity(
    identifier: &Identifier,
    preprocessed_lote: &PreprocessedLote,
) -> Result<Option<TrustedEntityInformation>, TrustListSubscriberError> {
    match identifier.r#type {
        IdentifierType::Did => Err(TrustListSubscriberError::UnsupportedIdentifierType(
            IdentifierType::Did,
        )),
        IdentifierType::Key => {
            let key = identifier.key.as_ref().ok_or_else(|| {
                TrustListSubscriberError::MappingError(format!(
                    "missing key on identifier `{}`",
                    identifier.id
                ))
            })?;
            find_matching_public_key(preprocessed_lote, key)
        }
        IdentifierType::Certificate | IdentifierType::CertificateAuthority => {
            let Some(active_certs) = identifier.active_certs() else {
                return Ok(None);
            };
            if active_certs.len() > 1 {
                return Err(TrustListSubscriberError::MultipleActiveCertificates(
                    identifier.id,
                ));
            }
            let Some(active_cert) = active_certs.first() else {
                return Ok(None);
            };

            // check fingerprint
            if let Some(idx) = preprocessed_lote
                .certificate_fingerprints
                .get(&active_cert.fingerprint)
            {
                return get(&preprocessed_lote.trusted_entities, *idx).map(Some);
            }

            let pem = extract_leaf_pem_from_chain(active_cert.chain.as_bytes())
                .error_while("parsing certificate value")?;
            let identifier_cert = pem.parse_x509()?;

            // check subject name
            if let Some(idx) = preprocessed_lote
                .subject_names
                .get(&identifier_cert.subject.to_string())
            {
                return get(&preprocessed_lote.trusted_entities, *idx).map(Some);
            }

            // check subject key identifier
            if let Some(ski) =
                identifier_cert.get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)?
            {
                let ski = Base64::encode_to_string(ski.value)?;
                if let Some(idx) = preprocessed_lote.subject_key_identifiers.get(&ski) {
                    return get(&preprocessed_lote.trusted_entities, *idx).map(Some);
                }
            }

            let key = active_cert.key.as_ref().ok_or_else(|| {
                TrustListSubscriberError::MappingError(format!(
                    "missing key on certificate `{}`",
                    active_cert.id
                ))
            })?;
            find_matching_public_key(preprocessed_lote, key)
        }
    }
}

fn find_matching_public_key(
    preprocessed_lote: &PreprocessedLote,
    key: &Key,
) -> Result<Option<TrustedEntityInformation>, TrustListSubscriberError> {
    let raw_public_key = Base64::encode_to_string(&key.public_key)?;
    if let Some(idx) = preprocessed_lote.public_keys.get(&raw_public_key) {
        return get(&preprocessed_lote.trusted_entities, *idx).map(Some);
    }
    Ok(None)
}

fn get(
    trusted_entities: &[TrustedEntityInformation],
    idx: usize,
) -> Result<TrustedEntityInformation, TrustListSubscriberError> {
    trusted_entities
        .get(idx)
        .ok_or_else(|| {
            TrustListSubscriberError::MappingError(format!(
                "preprocessed LoTE index {idx} out of bounds. Num elements: {}",
                trusted_entities.len()
            ))
        })
        .cloned()
}
