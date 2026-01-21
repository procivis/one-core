use shared_types::{CertificateId, DidId, IdentifierId, KeyId};

use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::did::{Did, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::key::Key;

#[derive(Default, Clone, Debug)]
pub struct KeyFilter {
    pub role: Option<KeyRole>,
    pub algorithms: Option<Vec<KeyAlgorithmType>>,
}

impl KeyFilter {
    pub fn role_filter(role: KeyRole) -> Self {
        Self {
            role: Some(role),
            ..Default::default()
        }
    }

    pub fn matches_related_key(&self, key: &RelatedKey) -> bool {
        let role_match = self
            .role
            .as_ref()
            .map(|role| *role == key.role)
            .unwrap_or(true);

        let algorithm_match = self.matches_key(&key.key);

        role_match && algorithm_match
    }

    pub fn matches_key(&self, key: &Key) -> bool {
        self.algorithms
            .as_ref()
            .map(|algorithms| {
                let Some(algorithm_type) = key.key_algorithm_type() else {
                    return false;
                };
                algorithms.contains(&algorithm_type)
            })
            .unwrap_or(true)
    }
}

#[derive(Default, Debug)]
pub struct KeySelection {
    pub key: Option<KeyId>,
    pub did: Option<DidId>,
    pub certificate: Option<CertificateId>,
    pub key_filter: Option<KeyFilter>,
}

impl From<KeyFilter> for KeySelection {
    fn from(value: KeyFilter) -> Self {
        Self {
            key_filter: Some(value),
            ..Default::default()
        }
    }
}

pub enum SelectedKey<'a> {
    Key(&'a Key),
    Certificate {
        certificate: &'a Certificate,
        key: &'a Key,
    },
    Did {
        did: &'a Did,
        key: &'a RelatedKey,
    },
}

impl SelectedKey<'_> {
    pub fn key(&self) -> &Key {
        match self {
            Self::Key(key) => key,
            Self::Certificate { key, .. } => key,
            Self::Did { key, .. } => &key.key,
        }
    }

    pub fn certificate(&self) -> Option<&Certificate> {
        match self {
            Self::Certificate { certificate, .. } => Some(certificate),
            _ => None,
        }
    }

    pub fn did(&self) -> Option<&Did> {
        match self {
            Self::Did { did, .. } => Some(did),
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
    #[error("Certificate {certificate_id} does not belong to identifier {identifier_id}")]
    CertificateNotFound {
        identifier_id: IdentifierId,
        certificate_id: CertificateId,
    },
    #[error("Certificate {certificate_id} is in invalid state `{state:?}`")]
    CertificateInvalidState {
        certificate_id: CertificateId,
        state: CertificateState,
    },
    #[error(
        "No active certificate available for identifier {identifier_id} matching filter `{key_filter:?}`"
    )]
    NoActiveMatchingCertificate {
        identifier_id: IdentifierId,
        key_filter: KeyFilter,
    },
    #[error("Key {key_id} does not belong to certificate {certificate_id}")]
    KeyCertificateMismatch {
        certificate_id: CertificateId,
        key_id: KeyId,
    },
    #[error("Key {key_id} does not belong to did {did_id}")]
    KeyDidMismatch { did_id: DidId, key_id: KeyId },
    #[error("Mapping error: {0}")]
    MappingError(String),
}

impl ErrorCodeMixin for KeySelectionError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MappingError(_) => ErrorCode::BR_0000,
            _ => ErrorCode::BR_0330,
        }
    }
}

impl Did {
    pub fn find_key(
        &self,
        key_id: &KeyId,
        filter: &KeyFilter,
    ) -> Result<&RelatedKey, KeySelectionError> {
        let mut same_id_keys = self
            .keys
            .as_ref()
            .ok_or_else(|| KeySelectionError::MappingError("keys is None".to_string()))?
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
            .ok_or_else(|| KeySelectionError::KeyNotMatchingFilter {
                key_id: *key_id,
                key_filter: filter.clone(),
            })
    }

    pub fn find_first_matching_key(
        &self,
        filter: &KeyFilter,
    ) -> Result<Option<&RelatedKey>, KeySelectionError> {
        Ok(self
            .keys
            .as_ref()
            .ok_or_else(|| KeySelectionError::MappingError("keys is None".to_string()))?
            .iter()
            .find(|entry| filter.matches_related_key(entry)))
    }
}

impl Certificate {
    pub fn has_matching_key(&self, filter: &KeyFilter) -> bool {
        self.key
            .as_ref()
            .map(|k| filter.matches_key(k))
            .unwrap_or(false)
    }
}

impl Identifier {
    pub(crate) fn select_key(
        &self,
        selection: KeySelection,
    ) -> Result<SelectedKey<'_>, KeySelectionError> {
        if self.is_remote {
            return Err(KeySelectionError::RemoteIdentifier);
        }
        let filter = selection.key_filter.clone().unwrap_or_default();
        match self.r#type {
            IdentifierType::Key => {
                self.throw_on_certificate_id(&selection)?;
                self.throw_on_did_id(&selection)?;

                let key = self.key.as_ref().ok_or(KeySelectionError::MappingError(
                    "Missing identifier key".to_owned(),
                ))?;

                if !filter.matches_key(key) {
                    return Err(KeySelectionError::NoKeyMatchingFilter {
                        identifier_id: self.id,
                        key_filter: filter,
                    });
                }

                if let Some(key_id) = selection.key
                    && key_id != key.id
                {
                    return Err(KeySelectionError::KeyNotFound {
                        identifier_id: self.id,
                        key_id,
                    });
                };
                Ok(SelectedKey::Key(key))
            }
            IdentifierType::Did => {
                self.throw_on_certificate_id(&selection)?;

                let did = self.did.as_ref().ok_or(KeySelectionError::MappingError(
                    "Missing identifier did".to_owned(),
                ))?;

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

                let key = match selection.key {
                    Some(key_id) => did.find_key(&key_id, &filter)?,
                    None => did.find_first_matching_key(&filter)?.ok_or(
                        KeySelectionError::NoKeyMatchingFilter {
                            identifier_id: self.id,
                            key_filter: filter,
                        },
                    )?,
                };

                Ok(SelectedKey::Did { did, key })
            }
            IdentifierType::Certificate | IdentifierType::CertificateAuthority => {
                self.throw_on_did_id(&selection)?;
                let certs = self
                    .certificates
                    .as_ref()
                    .ok_or(KeySelectionError::MappingError(
                        "Missing identifier certificates".to_owned(),
                    ))?;

                let certificate = match &selection.certificate {
                    Some(requested_id) => {
                        let requested_cert = certs
                            .iter()
                            .find(|cert| cert.id == *requested_id)
                            .ok_or(KeySelectionError::CertificateNotFound {
                                identifier_id: self.id,
                                certificate_id: *requested_id,
                            })?;
                        if requested_cert.state != CertificateState::Active {
                            return Err(KeySelectionError::CertificateInvalidState {
                                certificate_id: requested_cert.id,
                                state: requested_cert.state,
                            });
                        }
                        requested_cert
                    }
                    None => certs
                        .iter()
                        .find(|c| {
                            c.state == CertificateState::Active && c.has_matching_key(&filter)
                        })
                        .ok_or(KeySelectionError::NoActiveMatchingCertificate {
                            identifier_id: self.id,
                            key_filter: filter.clone(),
                        })?,
                };
                let key = certificate
                    .key
                    .as_ref()
                    .ok_or(KeySelectionError::MappingError(
                        "Missing certificate key".to_owned(),
                    ))?;

                if !filter.matches_key(key) {
                    return Err(KeySelectionError::KeyNotMatchingFilter {
                        key_id: key.id,
                        key_filter: filter,
                    });
                }

                if let Some(key_id) = selection.key
                    && key_id != key.id
                {
                    return Err(KeySelectionError::KeyCertificateMismatch {
                        certificate_id: certificate.id,
                        key_id,
                    });
                }

                Ok(SelectedKey::Certificate { certificate, key })
            }
        }
    }

    fn throw_on_certificate_id(&self, selection: &KeySelection) -> Result<(), KeySelectionError> {
        if selection.certificate.is_some() {
            return Err(KeySelectionError::SelectionNotApplicableForType {
                identifier_id: self.id,
                id_type: "Certificate".to_string(),
                identifier_type: self.r#type,
            });
        }
        Ok(())
    }

    fn throw_on_did_id(&self, selection: &KeySelection) -> Result<(), KeySelectionError> {
        if selection.did.is_some() {
            return Err(KeySelectionError::SelectionNotApplicableForType {
                identifier_id: self.id,
                id_type: "Did".to_string(),
                identifier_type: self.r#type,
            });
        }
        Ok(())
    }
}
