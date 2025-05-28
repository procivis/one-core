use shared_types::{CertificateId, DidId, KeyId};

use crate::model::certificate::{Certificate, CertificateState};
use crate::model::did::{Did, KeyRole};
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

pub(crate) fn entities_for_local_active_identifier(
    key_id: Option<KeyId>,
    did_id: Option<DidId>,
    certificate_id: Option<CertificateId>,
    identifier: &Identifier,
) -> Result<IdentifierEntitySelection, ServiceError> {
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

            let key = match key_id {
                Some(key_id) => did
                    .find_key(&key_id, KeyRole::Authentication)?
                    .ok_or(ValidationError::KeyNotFound)?,
                None => did.find_first_key_by_role(KeyRole::Authentication)?.ok_or(
                    ValidationError::InvalidKey("No authentication key found".to_string()),
                )?,
            };

            Ok(IdentifierEntitySelection::Did { did, key })
        }
        IdentifierType::Certificate => {
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
