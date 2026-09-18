use rcgen::KeyUsagePurpose;
use shared_types::{CertificateId, DidId, IdentifierId, KeyId};
use x509_parser::pem::Pem;
use x509_parser::prelude::KeyUsage;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::certificate::{Certificate, CertificateRole, CertificateState};
use crate::model::did::{Did, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierData, IdentifierType};
use crate::model::key::Key;

#[derive(Default, Clone, Debug)]
pub struct KeyFilter {
    id: Option<KeyId>,
    did_role: Option<KeyRole>,
    algorithms: Option<Vec<KeyAlgorithmType>>,
}

impl KeyFilter {
    pub fn did_role(role: KeyRole) -> Self {
        Self {
            did_role: Some(role),
            ..Default::default()
        }
    }

    pub fn id(id: Option<KeyId>) -> Self {
        Self {
            id,
            ..Default::default()
        }
    }

    pub fn and_id(mut self, id: Option<KeyId>) -> Self {
        self.id = id;
        self
    }

    pub fn algorithms(algorithms: Vec<KeyAlgorithmType>) -> Result<Self, KeySelectionError> {
        if algorithms.is_empty() {
            return Err(KeySelectionError::ImpossibleFilter(
                "Empty algorithms".to_string(),
            ));
        }
        Ok(Self {
            algorithms: Some(algorithms),
            ..Default::default()
        })
    }

    pub fn and_algorithms(
        mut self,
        algorithms: Vec<KeyAlgorithmType>,
    ) -> Result<Self, KeySelectionError> {
        if algorithms.is_empty() {
            return Err(KeySelectionError::ImpossibleFilter(
                "Empty algorithms".to_string(),
            ));
        }
        self.algorithms = Some(algorithms);
        Ok(self)
    }

    pub fn matches_related_key(&self, key: &RelatedKey) -> bool {
        let role_match = self
            .did_role
            .as_ref()
            .map(|role| *role == key.role)
            .unwrap_or(true);

        let algorithm_match = self.matches_key(&key.key);

        role_match && algorithm_match
    }

    pub fn matches_key(&self, key: &Key) -> bool {
        if let Some(key_id) = self.id.as_ref()
            && key_id != &key.id
        {
            return false;
        }
        self.algorithms
            .as_ref()
            .map(|algorithms| {
                let Ok(algorithm_type) = key.key_algorithm_type() else {
                    return false;
                };
                algorithms.contains(&algorithm_type)
            })
            .unwrap_or(true)
    }
}

#[derive(Clone, Debug)]
pub struct CertificateFilter {
    id: Option<CertificateId>,
    role: Option<CertificateRole>,
    key_usage: Option<Vec<KeyUsagePurpose>>,
    allowed_states: Option<Vec<CertificateState>>,
}

impl Default for CertificateFilter {
    fn default() -> Self {
        Self {
            allowed_states: Some(vec![CertificateState::Active]),
            id: None,
            role: None,
            key_usage: None,
        }
    }
}

impl CertificateFilter {
    pub fn id(id: Option<CertificateId>) -> Self {
        Self {
            id,
            ..Default::default()
        }
    }

    pub fn key_usage(usage: Vec<KeyUsagePurpose>) -> Self {
        Self {
            key_usage: Some(usage),
            ..Default::default()
        }
    }

    pub fn and_id(mut self, id: Option<CertificateId>) -> Self {
        self.id = id;
        self
    }

    pub fn role_filter(role: CertificateRole) -> Self {
        Self {
            role: Some(role),
            ..Default::default()
        }
    }

    pub fn allow_all_states(mut self) -> Self {
        self.allowed_states = None;
        self
    }

    pub fn matches_certificate(&self, certificate: &Certificate) -> bool {
        if let Some(id) = self.id.as_ref()
            && id != &certificate.id
        {
            return false;
        }
        if let Some(key_usage) = &self.key_usage
            && !certificate.matches_key_usage(key_usage)
        {
            return false;
        }
        if let Some(allowed_states) = &self.allowed_states
            && !allowed_states.contains(&certificate.state)
        {
            return false;
        }
        if let Some(role) = self.role
            && !certificate.roles.contains(&role)
        {
            return false;
        }
        true
    }
}

#[derive(Default, Debug)]
pub struct KeySelection {
    pub did: Option<DidId>,
    pub key: KeyFilter,
    pub certificate: CertificateFilter,
}

impl From<KeyFilter> for KeySelection {
    fn from(value: KeyFilter) -> Self {
        Self {
            key: value,
            ..Default::default()
        }
    }
}

pub enum SelectedKey {
    Key(Box<Key>),
    Certificate {
        certificate: Box<Certificate>,
        key: Box<Key>,
    },
    Did {
        did: Box<Did>,
        key: Box<RelatedKey>,
    },
}

impl SelectedKey {
    pub fn key(&self) -> &Key {
        match self {
            Self::Key(key) => key,
            Self::Certificate { key, .. } => key,
            Self::Did { key, .. } => &key.key,
        }
    }

    pub fn certificate(&self) -> Option<&Certificate> {
        match self {
            Self::Certificate { certificate, .. } => Some(certificate.as_ref()),
            _ => None,
        }
    }

    pub fn did(&self) -> Option<&Did> {
        match self {
            Self::Did { did, .. } => Some(did.as_ref()),
            _ => None,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum KeySelectionError {
    #[error(
        "{id_type} id must not be specified for identifier {identifier_id} of type `{identifier_type}`"
    )]
    SelectionNotApplicableForType {
        identifier_id: IdentifierId,
        id_type: String,
        identifier_type: IdentifierType,
    },
    #[error("Key cannot be selected from remote identifier")]
    RemoteIdentifier,
    #[error("Key {key_id} does not belong to identifier {identifier_id}")]
    KeyNotFound {
        identifier_id: IdentifierId,
        key_id: KeyId,
    },
    #[error("Did {did_id} does not belong to identifier {identifier_id}")]
    DidIdentifierMismatch {
        identifier_id: IdentifierId,
        did_id: DidId,
    },
    #[error("Did {did_id} is deactivated")]
    DidDeactivated { did_id: DidId },
    #[error("No key matching filter `{key_filter:?}` found on identifier {identifier_id}")]
    NoKeyMatchingFilter {
        identifier_id: IdentifierId,
        key_filter: KeyFilter,
    },
    #[error("Key {key_id} does not match filter `{key_filter:?}`")]
    KeyNotMatchingFilter {
        key_id: KeyId,
        key_filter: KeyFilter,
    },
    #[error("Certificate {certificate_id} does not match filter `{certificate_filter:?}`")]
    CertificateNotMatchingFilter {
        certificate_id: CertificateId,
        certificate_filter: CertificateFilter,
    },
    #[error(
        "No certificate matching filters available for `identifier` ({identifier_id}): certificate filter `{certificate_filter:?}`: key filter `{key_filter:?}`"
    )]
    NoMatchingCertificate {
        identifier_id: IdentifierId,
        key_filter: KeyFilter,
        certificate_filter: Box<CertificateFilter>,
    },
    #[error("Key {key_id} does not belong to certificate {certificate_id}")]
    KeyCertificateMismatch {
        certificate_id: CertificateId,
        key_id: KeyId,
    },
    #[error("Key {key_id} does not belong to did {did_id}")]
    KeyDidMismatch { did_id: DidId, key_id: KeyId },
    #[error("Impossible filter: `{0}`")]
    ImpossibleFilter(String),
    #[error("Mapping error: {0}")]
    MappingError(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for KeySelectionError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::CertificateNotMatchingFilter { .. } => ErrorCode::BR_0222,
            Self::Nested(nested) => nested.error_code(),
            _ => ErrorCode::BR_0330,
        }
    }
}

impl Did {
    pub async fn find_key(
        &self,
        key_id: &KeyId,
        filter: &KeyFilter,
    ) -> Result<RelatedKey, KeySelectionError> {
        let keys = self.keys.as_ref().await?;
        let mut same_id_keys = keys
            .as_ref()
            .iter()
            .filter(|entry| &entry.key.id == key_id)
            .peekable();

        if same_id_keys.peek().is_none() {
            return Err(KeySelectionError::KeyDidMismatch {
                did_id: self.id,
                key_id: *key_id,
            });
        }

        same_id_keys
            .find(|entry| filter.matches_related_key(entry))
            .map(ToOwned::to_owned)
            .ok_or_else(|| KeySelectionError::KeyNotMatchingFilter {
                key_id: *key_id,
                key_filter: filter.clone(),
            })
    }

    pub async fn find_first_matching_key(
        &self,
        filter: &KeyFilter,
    ) -> Result<Option<RelatedKey>, KeySelectionError> {
        Ok(self
            .keys
            .as_ref()
            .await?
            .as_ref()
            .iter()
            .find(|entry| filter.matches_related_key(entry))
            .cloned())
    }

    pub async fn find_matching_keys(
        &self,
        filter: &KeyFilter,
    ) -> Result<Vec<RelatedKey>, KeySelectionError> {
        Ok(self
            .keys
            .as_ref()
            .await?
            .as_ref()
            .iter()
            .filter(|entry| filter.matches_related_key(entry))
            .map(ToOwned::to_owned)
            .collect())
    }
}

impl Certificate {
    pub async fn has_matching_key(&self, filter: &KeyFilter) -> Result<bool, KeySelectionError> {
        Ok(if let Some(key) = self.key.as_ref() {
            let key = key.as_ref().await?;
            filter.matches_key(&key)
        } else {
            false
        })
    }

    fn matches_key_usage(&self, certificate_key_usage: &[KeyUsagePurpose]) -> bool {
        let Some(Ok(pem)) = Pem::iter_from_buffer(self.chain.as_bytes()).next() else {
            return false;
        };
        let Ok(cert) = pem.parse_x509() else {
            return false;
        };
        let Ok(Some(key_usage)) = cert.key_usage() else {
            return false;
        };
        certificate_key_usage
            .iter()
            .all(|key_usage_purpose| key_usage_matches(key_usage.value, key_usage_purpose))
    }

    async fn key(&self) -> Result<Key, KeySelectionError> {
        Ok(self
            .key
            .as_ref()
            .ok_or(KeySelectionError::MappingError(
                "Missing certificate key".to_owned(),
            ))?
            .as_ref()
            .await?
            .to_owned())
    }
}

fn key_usage_matches(key_usage: &KeyUsage, key_usage_purpose: &KeyUsagePurpose) -> bool {
    match key_usage_purpose {
        KeyUsagePurpose::DigitalSignature => key_usage.digital_signature(),
        KeyUsagePurpose::ContentCommitment => key_usage.non_repudiation(),
        KeyUsagePurpose::KeyEncipherment => key_usage.key_encipherment(),
        KeyUsagePurpose::DataEncipherment => key_usage.data_encipherment(),
        KeyUsagePurpose::KeyAgreement => key_usage.key_agreement(),
        KeyUsagePurpose::KeyCertSign => key_usage.key_cert_sign(),
        KeyUsagePurpose::CrlSign => key_usage.crl_sign(),
        KeyUsagePurpose::EncipherOnly => key_usage.encipher_only(),
        KeyUsagePurpose::DecipherOnly => key_usage.decipher_only(),
    }
}

impl Identifier {
    pub(crate) async fn select_key(
        &self,
        selection: KeySelection,
    ) -> Result<SelectedKey, KeySelectionError> {
        if self.is_remote {
            return Err(KeySelectionError::RemoteIdentifier);
        }
        let filter = &selection.key;
        match &self.data {
            IdentifierData::Key(key) => {
                self.throw_on_certificate_id(&selection)?;
                self.throw_on_did_id(&selection)?;

                let key = key.as_ref().await?;

                if !filter.matches_key(&key) {
                    return Err(KeySelectionError::NoKeyMatchingFilter {
                        identifier_id: self.id,
                        key_filter: filter.clone(),
                    });
                }

                if let Some(key_id) = filter.id
                    && key_id != key.id
                {
                    return Err(KeySelectionError::KeyNotFound {
                        identifier_id: self.id,
                        key_id,
                    });
                };
                Ok(SelectedKey::Key(Box::new(key.as_ref().clone())))
            }
            IdentifierData::Did(did) => {
                self.throw_on_certificate_id(&selection)?;

                let did = did.as_ref().await?.clone();

                if did.deactivated {
                    return Err(KeySelectionError::DidDeactivated { did_id: did.id });
                }
                if let Some(did_id) = selection.did
                    && did.id != did_id
                {
                    return Err(KeySelectionError::DidIdentifierMismatch {
                        identifier_id: self.id,
                        did_id,
                    });
                }

                let key = did.find_first_matching_key(filter).await?.ok_or(
                    KeySelectionError::NoKeyMatchingFilter {
                        identifier_id: self.id,
                        key_filter: filter.clone(),
                    },
                )?;
                Ok(SelectedKey::Did {
                    did: Box::new(did),
                    key: Box::new(key),
                })
            }
            IdentifierData::Certificate(certificates)
            | IdentifierData::CertificateAuthority(certificates) => {
                self.throw_on_did_id(&selection)?;
                let certs = certificates.as_ref().await?;
                let mut selected_cert = None;
                for c in certs.iter() {
                    if selection.certificate.matches_certificate(c)
                        && c.has_matching_key(filter).await?
                    {
                        selected_cert = Some(c);
                        break;
                    }
                }
                let certificate =
                    selected_cert.ok_or(KeySelectionError::NoMatchingCertificate {
                        identifier_id: self.id,
                        key_filter: filter.clone(),
                        certificate_filter: Box::new(selection.certificate.clone()),
                    })?;
                Ok(SelectedKey::Certificate {
                    key: Box::new(certificate.key().await?),
                    certificate: Box::new(certificate.clone()),
                })
            }
        }
    }

    pub(crate) async fn list_keys(
        &self,
        key_filter: Option<KeyFilter>,
        certificate_filter: Option<CertificateFilter>,
    ) -> Result<Vec<SelectedKey>, KeySelectionError> {
        if self.is_remote {
            return Err(KeySelectionError::RemoteIdentifier);
        }
        let filter = key_filter.unwrap_or_default();
        match &self.data {
            IdentifierData::Key(key) => {
                let key = key.as_ref().await?;

                if !filter.matches_key(&key) {
                    return Err(KeySelectionError::NoKeyMatchingFilter {
                        identifier_id: self.id,
                        key_filter: filter,
                    });
                }
                Ok(vec![SelectedKey::Key(Box::new(key.as_ref().clone()))])
            }
            IdentifierData::Did(did) => {
                let did = did.as_ref().await?.clone();

                if did.deactivated {
                    return Err(KeySelectionError::DidDeactivated { did_id: did.id });
                }

                let matching_keys = did.find_matching_keys(&filter).await?;
                if matching_keys.is_empty() {
                    return Err(KeySelectionError::NoKeyMatchingFilter {
                        identifier_id: self.id,
                        key_filter: filter,
                    });
                }
                Ok(matching_keys
                    .into_iter()
                    .map(|key| SelectedKey::Did {
                        did: Box::new(did.clone()),
                        key: Box::new(key),
                    })
                    .collect())
            }
            IdentifierData::Certificate(certs) | IdentifierData::CertificateAuthority(certs) => {
                let certificate_filter = certificate_filter.unwrap_or_default();
                let certs = certs.as_ref().await?;

                let mut certificates = vec![];
                for certificate in certs.iter() {
                    if !certificate_filter.matches_certificate(certificate)
                        || !certificate.has_matching_key(&filter).await?
                    {
                        continue;
                    }
                    certificates.push(SelectedKey::Certificate {
                        key: Box::new(certificate.key().await?),
                        certificate: Box::new(certificate.clone()),
                    });
                }

                if certificates.is_empty() {
                    return Err(KeySelectionError::NoMatchingCertificate {
                        identifier_id: self.id,
                        key_filter: filter.clone(),
                        certificate_filter: Box::new(certificate_filter.clone()),
                    });
                }
                Ok(certificates)
            }
        }
    }

    fn throw_on_certificate_id(&self, selection: &KeySelection) -> Result<(), KeySelectionError> {
        if selection.certificate.id.is_some() {
            return Err(KeySelectionError::SelectionNotApplicableForType {
                identifier_id: self.id,
                id_type: "Certificate".to_string(),
                identifier_type: self.data.r#type(),
            });
        }
        Ok(())
    }

    fn throw_on_did_id(&self, selection: &KeySelection) -> Result<(), KeySelectionError> {
        if selection.did.is_some() {
            return Err(KeySelectionError::SelectionNotApplicableForType {
                identifier_id: self.id,
                id_type: "Did".to_string(),
                identifier_type: self.data.r#type(),
            });
        }
        Ok(())
    }
}
