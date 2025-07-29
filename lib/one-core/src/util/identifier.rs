use shared_types::{CertificateId, DidId, KeyId};

use crate::model::certificate::{Certificate, CertificateState};
use crate::model::did::{Did, KeyFilter};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::key::Key;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};

pub(crate) enum IdentifierEntitySelection<'a> {
    #[allow(unused)]
    Key(&'a Key),
    Certificate {
        certificate: &'a Certificate,
        key: &'a Key,
    },
    Did {
        did: &'a Did,
        key: &'a Key,
    },
}

pub(crate) fn entities_for_local_active_identifier<'a>(
    identifier: &'a Identifier,
    key_filter: &KeyFilter,
    key_id: Option<KeyId>,
    did_id: Option<DidId>,
    certificate_id: Option<CertificateId>,
) -> Result<IdentifierEntitySelection<'a>, ServiceError> {
    if identifier.state != IdentifierState::Active {
        return Err(BusinessLogicError::IdentifierIsDeactivated(identifier.id).into());
    }

    if identifier.is_remote {
        return Err(BusinessLogicError::IncompatibleIdentifierType {
            reason: "identifier is remote".to_string(),
        }
        .into());
    }

    match identifier.r#type {
        IdentifierType::Did => {
            if certificate_id.is_some() {
                return Err(ServiceError::ValidationError(
                    "Certificate cannot be specified for identifier of type did".to_string(),
                ));
            }

            let did = identifier.did.as_ref().ok_or(ServiceError::MappingError(
                "missing identifier did".to_string(),
            ))?;

            if let Some(did_id) = did_id {
                if did.id != did_id {
                    return Err(ServiceError::ValidationError(
                        "Mismatching identifier and did specified".to_string(),
                    ));
                }
            }

            if did.deactivated {
                return Err(BusinessLogicError::DidIsDeactivated(did.id).into());
            }

            if did.did_type.is_remote() {
                return Err(BusinessLogicError::IncompatibleDidType {
                    reason: "did is remote".to_string(),
                }
                .into());
            }

            let key =
                &match key_id {
                    Some(key_id) => did
                        .find_key(&key_id, key_filter)?
                        .ok_or(ValidationError::KeyNotFound)?,
                    None => did.find_first_matching_key(key_filter)?.ok_or(
                        ValidationError::InvalidKey("No authentication key found".to_string()),
                    )?,
                }
                .key;

            Ok(IdentifierEntitySelection::Did { did, key })
        }
        IdentifierType::Certificate => {
            if did_id.is_some() {
                return Err(ServiceError::ValidationError(
                    "Did cannot be specified for identifier of type certificate".to_string(),
                ));
            }
            let certificates =
                identifier
                    .certificates
                    .as_ref()
                    .ok_or(ServiceError::MappingError(
                        "missing identifier certificates".to_string(),
                    ))?;

            let certificate = match certificate_id {
                Some(certificate_id) => {
                    let certificate = certificates
                        .iter()
                        .find(|certificate| certificate.id == certificate_id)
                        .ok_or(ServiceError::ValidationError(
                            "Mismatching identifier and certificate specified".to_string(),
                        ))?;

                    if certificate.state != CertificateState::Active {
                        return Err(ServiceError::ValidationError(
                            "Selected certificate not active".to_string(),
                        ));
                    }
                    certificate
                }
                // no certificate selected by user, pick an active
                None => certificates
                    .iter()
                    .find(|certificate| certificate.state == CertificateState::Active)
                    .ok_or(ServiceError::ValidationError(
                        "No active certificate found".to_string(),
                    ))?,
            };

            let key = certificate.key.as_ref().ok_or(ServiceError::MappingError(
                "missing certificate key".to_string(),
            ))?;

            validate_key_id_matches(key_id, key)?;
            Ok(IdentifierEntitySelection::Certificate { certificate, key })
        }
        IdentifierType::Key => {
            if did_id.is_some() {
                return Err(ServiceError::ValidationError(
                    "Did cannot be specified for identifier of type key".to_string(),
                ));
            }
            if certificate_id.is_some() {
                return Err(ServiceError::ValidationError(
                    "Certificate cannot be specified for identifier of type key".to_string(),
                ));
            }

            let key = identifier.key.as_ref().ok_or(ServiceError::MappingError(
                "missing identifier key".to_string(),
            ))?;
            validate_key_id_matches(key_id, key)?;
            Ok(IdentifierEntitySelection::Key(key))
        }
    }
}

fn validate_key_id_matches(key_id: Option<KeyId>, key: &Key) -> Result<(), ServiceError> {
    if let Some(key_id) = key_id {
        if key.id != key_id {
            return Err(ServiceError::ValidationError(
                "Mismatching key specified".to_string(),
            ));
        }
    }
    Ok(())
}
