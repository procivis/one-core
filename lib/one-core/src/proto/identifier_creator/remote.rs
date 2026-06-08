use shared_types::{DidId, DidValue};
use standardized_types::jwk::PublicJwk;
use uuid::Uuid;

use super::creator::IdentifierCreatorProto;
use super::{Error, IdentifierName};
use crate::error::ContextWithErrorCode;
use crate::model::certificate::{
    Certificate, CertificateFilterValue, CertificateListQuery, CertificateState,
};
use crate::model::did::{Did, DidType};
use crate::model::identifier::{
    Identifier, IdentifierFilterValue, IdentifierListQuery, IdentifierRelations, IdentifierState,
    IdentifierType,
};
use crate::model::key::{Key, KeyFilterValue, KeyListQuery};
use crate::model::list_filter::ListFilterValue;
use crate::model::organisation::Organisation;
use crate::proto::certificate_validator::{CertificateValidationOptions, ParsedCertificate};
use crate::proto::identifier_creator::RemoteIdentifierRelation;
use crate::provider::credential_formatter::model::IdentifierDetails;

impl IdentifierCreatorProto {
    pub(super) async fn get_or_create_did_and_identifier(
        &self,
        organisation: &Option<Organisation>,
        did_value: &DidValue,
        name: IdentifierName,
    ) -> Result<(Did, Identifier), Error> {
        let now = crate::clock::now_utc();

        let did = match self
            .did_repository
            .get_did_by_value(did_value, organisation.as_ref().map(|org| Some(org.id)))
            .await
            .error_while("getting did")?
        {
            Some(did) => did,
            None => {
                let id = Uuid::new_v4();
                let did_method = self
                    .did_method_provider
                    .get_did_method_id(did_value)
                    .error_while("getting did method")?;
                let did = Did {
                    id: DidId::from(id),
                    created_date: now,
                    last_modified: now,
                    name: name.for_id(id),
                    organisation: organisation.to_owned().map(Into::into),
                    did: did_value.to_owned(),
                    did_method,
                    did_type: DidType::Remote,
                    keys: Default::default(),
                    deactivated: false,
                    log: None,
                };
                self.did_repository
                    .create_did(did.clone())
                    .await
                    .error_while("creating did")?;
                did
            }
        };

        let identifier = match self
            .identifier_repository
            .get_from_did_id(
                did.id,
                &IdentifierRelations {
                    did: Some(Default::default()),
                    key: Some(Default::default()),
                    certificates: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting did")?
        {
            Some(identifier) => identifier,
            None => {
                let identifier = Identifier {
                    id: Uuid::new_v4().into(),
                    created_date: now,
                    last_modified: now,
                    name: did.name.to_owned(),
                    r#type: IdentifierType::Did,
                    is_remote: did.did_type == DidType::Remote,
                    state: IdentifierState::Active,
                    deleted_at: None,
                    organisation: organisation.to_owned(),
                    did: Some(did.to_owned()),
                    key: None,
                    certificates: None,
                    trust_information: None,
                };
                self.identifier_repository
                    .create(identifier.clone())
                    .await
                    .error_while("creating identifier")?;
                identifier
            }
        };

        Ok((did, identifier))
    }

    pub(super) async fn get_or_create_certificate_identifier(
        &self,
        organisation: &Option<Organisation>,
        chain: String,
        fingerprint: String,
        name: IdentifierName,
    ) -> Result<(Certificate, Identifier), Error> {
        let organisation_id = organisation
            .as_ref()
            .map(|org| CertificateFilterValue::OrganisationId(org.id));

        let list = self
            .certificate_repository
            .list(CertificateListQuery {
                filtering: Some(
                    CertificateFilterValue::Fingerprint(fingerprint.to_owned()).condition()
                        & organisation_id,
                ),
                ..Default::default()
            })
            .await
            .error_while("getting certificates")?;

        if let Some(certificate) = list.values.into_iter().next() {
            let mut identifier = self
                .identifier_repository
                .get(certificate.identifier_id, &Default::default())
                .await
                .error_while("getting identifier")?
                .ok_or(Error::MappingError(
                    "Certificate identifier not found".to_string(),
                ))?;
            // Back-fill the certificates relation, consistent with the did/key paths.
            identifier.certificates = Some(vec![certificate.clone()]);

            return Ok((certificate, identifier));
        }

        let ParsedCertificate {
            attributes,
            subject_common_name,
            ..
        } = self
            .certificate_validator
            .parse_pem_chain(&chain, CertificateValidationOptions::no_validation())
            .await
            .error_while("parsing PEM chain")?;

        if attributes.fingerprint != fingerprint {
            return Err(Error::MappingError(format!(
                "Fingerprint {fingerprint} doesn't match provided certificate"
            )));
        }

        let now = crate::clock::now_utc();
        let identifier_id = Uuid::new_v4().into();
        let display_name = name.for_id(identifier_id);

        let mut identifier = Identifier {
            id: identifier_id,
            created_date: now,
            last_modified: now,
            name: display_name.clone(),
            r#type: IdentifierType::Certificate,
            is_remote: true,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: organisation.to_owned(),
            did: None,
            key: None,
            certificates: None,
            trust_information: None,
        };
        self.identifier_repository
            .create(identifier.clone())
            .await
            .error_while("creating identifier")?;

        let certificate = Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            organisation: organisation.to_owned().map(Into::into),
            created_date: now,
            last_modified: now,
            deleted_at: None,
            expiry_date: attributes.not_after,
            name: subject_common_name.unwrap_or(display_name),
            chain,
            fingerprint,
            state: CertificateState::Active,
            roles: vec![],
            key: None,
        };
        self.certificate_repository
            .create(certificate.clone())
            .await
            .error_while("creating certificate")?;

        // Back-fill the certificates relation, consistent with the did/key paths.
        identifier.certificates = Some(vec![certificate.clone()]);

        Ok((certificate, identifier))
    }

    pub(super) async fn get_or_create_key_identifier(
        &self,
        organisation: Option<&Organisation>,
        public_key: &PublicJwk,
        name: IdentifierName,
    ) -> Result<(Key, Identifier), Error> {
        let parsed_key = self
            .key_algorithm_provider
            .parse_jwk(public_key)
            .error_while("parsing JWK")?;
        let organisation_id = organisation.as_ref().map(|org| org.id);
        let now = crate::clock::now_utc();

        let list = self
            .key_repository
            .get_key_list(KeyListQuery {
                filtering: Some(
                    KeyFilterValue::RawPublicKey(parsed_key.key.public_key_as_raw()).condition()
                        & KeyFilterValue::KeyTypes(vec![parsed_key.algorithm_type.to_string()])
                        & organisation_id.map(KeyFilterValue::OrganisationId),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting keys")?;

        let key = if let Some(key) = list.values.into_iter().next() {
            let identifier = self
                .identifier_repository
                .get_identifier_list(IdentifierListQuery {
                    filtering: Some(
                        IdentifierFilterValue::KeyIds(vec![key.id]).condition()
                            & IdentifierFilterValue::Types(vec![IdentifierType::Key])
                            & organisation_id.map(IdentifierFilterValue::OrganisationId),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("getting identifiers")?
                .values
                .into_iter()
                .next();

            if let Some(mut identifier) = identifier {
                // Back-fill relations
                identifier.key = Some(key.clone());
                identifier.organisation = organisation.cloned();
                return Ok((key, identifier));
            };

            key
        } else {
            let key_id = Uuid::new_v4().into();
            let key = Key {
                id: key_id,
                created_date: now,
                last_modified: now,
                name: name.for_id(key_id),
                organisation: organisation
                    .ok_or(Error::MappingError("missing organisation".to_string()))?
                    .to_owned()
                    .into(),
                public_key: parsed_key.key.public_key_as_raw(),
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: parsed_key.algorithm_type.to_string(),
            };

            self.key_repository
                .create_key(key.clone())
                .await
                .error_while("creating key")?;
            key
        };

        let identifier_id = Uuid::new_v4().into();
        let identifier = Identifier {
            id: identifier_id,
            created_date: now,
            last_modified: now,
            name: name.for_id(identifier_id),
            r#type: IdentifierType::Key,
            is_remote: true,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: organisation.cloned(),
            did: None,
            key: Some(key.clone()),
            certificates: None,
            trust_information: None,
        };
        self.identifier_repository
            .create(identifier.clone())
            .await
            .error_while("creating identifier")?;

        Ok((key, identifier))
    }

    #[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
    pub(super) async fn find_identifier(
        &self,
        organisation: &Option<Organisation>,
        details: &IdentifierDetails,
    ) -> Result<Option<(Identifier, RemoteIdentifierRelation)>, Error> {
        match details {
            IdentifierDetails::Did(did_value) => {
                let Some(did) = self
                    .did_repository
                    .get_did_by_value(did_value, organisation.as_ref().map(|org| Some(org.id)))
                    .await
                    .error_while("getting did")?
                else {
                    return Ok(None);
                };

                let Some(identifier) = self
                    .identifier_repository
                    .get_from_did_id(
                        did.id,
                        &IdentifierRelations {
                            did: Some(Default::default()),
                            ..Default::default()
                        },
                    )
                    .await
                    .error_while("getting identifier")?
                else {
                    return Ok(None);
                };

                Ok(Some((identifier, RemoteIdentifierRelation::Did(did))))
            }
            IdentifierDetails::Certificate(certificate_details) => {
                let organisation_id = organisation
                    .as_ref()
                    .map(|org| CertificateFilterValue::OrganisationId(org.id));

                let list = self
                    .certificate_repository
                    .list(CertificateListQuery {
                        filtering: Some(
                            CertificateFilterValue::Fingerprint(
                                certificate_details.fingerprint.to_owned(),
                            )
                            .condition()
                                & organisation_id,
                        ),
                        ..Default::default()
                    })
                    .await
                    .error_while("getting certificates")?;

                let Some(certificate) = list.values.into_iter().next() else {
                    return Ok(None);
                };

                let Some(mut identifier) = self
                    .identifier_repository
                    .get(certificate.identifier_id, &Default::default())
                    .await
                    .error_while("getting identifier")?
                else {
                    return Ok(None);
                };
                // Back-fill the certificates relation, consistent with the did path.
                identifier.certificates = Some(vec![certificate.clone()]);

                Ok(Some((
                    identifier,
                    RemoteIdentifierRelation::Certificate(certificate),
                )))
            }
            IdentifierDetails::Key(public_jwk) => {
                let parsed_key = self
                    .key_algorithm_provider
                    .parse_jwk(public_jwk)
                    .error_while("parsing JWK")?;
                let organisation_id = organisation.as_ref().map(|org| org.id);

                let list = self
                    .key_repository
                    .get_key_list(KeyListQuery {
                        filtering: Some(
                            KeyFilterValue::RawPublicKey(parsed_key.key.public_key_as_raw())
                                .condition()
                                & KeyFilterValue::KeyTypes(vec![
                                    parsed_key.algorithm_type.to_string(),
                                ])
                                & organisation_id.map(KeyFilterValue::OrganisationId),
                        ),
                        ..Default::default()
                    })
                    .await
                    .error_while("getting keys")?;

                let Some(key) = list.values.into_iter().next() else {
                    return Ok(None);
                };

                let Some(identifier) = self
                    .identifier_repository
                    .get_identifier_list(IdentifierListQuery {
                        filtering: Some(
                            IdentifierFilterValue::KeyIds(vec![key.id]).condition()
                                & IdentifierFilterValue::Types(vec![IdentifierType::Key])
                                & organisation_id.map(IdentifierFilterValue::OrganisationId),
                        ),
                        ..Default::default()
                    })
                    .await
                    .error_while("getting identifiers")?
                    .values
                    .into_iter()
                    .next()
                else {
                    return Ok(None);
                };

                Ok(Some((identifier, RemoteIdentifierRelation::Key(key))))
            }
        }
    }
}
