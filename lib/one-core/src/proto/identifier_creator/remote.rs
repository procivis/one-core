use shared_types::{DidId, DidValue};
use standardized_types::jwk::PublicJwk;
use time::OffsetDateTime;
use uuid::Uuid;

use super::IdentifierRole;
use super::creator::IdentifierCreatorProto;
use crate::model::certificate::{
    Certificate, CertificateFilterValue, CertificateListQuery, CertificateState,
};
use crate::model::did::{Did, DidRelations, DidType};
use crate::model::identifier::{
    Identifier, IdentifierFilterValue, IdentifierListQuery, IdentifierRelations, IdentifierState,
    IdentifierType,
};
use crate::model::key::{Key, KeyFilterValue, KeyListQuery};
use crate::model::list_filter::ListFilterValue;
use crate::model::organisation::Organisation;
use crate::proto::certificate_validator::{CertificateValidationOptions, ParsedCertificate};
use crate::service::error::{MissingProviderError, ServiceError};

impl IdentifierCreatorProto {
    pub(super) async fn get_or_create_did_and_identifier(
        &self,
        organisation: &Option<Organisation>,
        did_value: &DidValue,
        role: IdentifierRole,
    ) -> Result<(Did, Identifier), ServiceError> {
        let now = OffsetDateTime::now_utc();

        let did = match self
            .did_repository
            .get_did_by_value(
                did_value,
                organisation.as_ref().map(|org| Some(org.id)),
                &DidRelations::default(),
            )
            .await?
        {
            Some(did) => did,
            None => {
                let id = Uuid::new_v4();
                let did_method = self
                    .did_method_provider
                    .get_did_method_id(did_value)
                    .ok_or(ServiceError::MissingProvider(
                        MissingProviderError::DidMethod(did_value.method().to_string()),
                    ))?;
                let did = Did {
                    id: DidId::from(id),
                    created_date: now,
                    last_modified: now,
                    name: format!("{role} {id}"),
                    organisation: organisation.to_owned(),
                    did: did_value.to_owned(),
                    did_method,
                    did_type: DidType::Remote,
                    keys: None,
                    deactivated: false,
                    log: None,
                };
                self.did_repository.create_did(did.clone()).await?;
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
            .await?
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
                };
                self.identifier_repository
                    .create(identifier.clone())
                    .await?;
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
        role: IdentifierRole,
    ) -> Result<(Certificate, Identifier), ServiceError> {
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
            .await?;

        if let Some(certificate) = list.values.into_iter().next() {
            let identifier = self
                .identifier_repository
                .get(certificate.identifier_id, &Default::default())
                .await?
                .ok_or(ServiceError::MappingError(
                    "Certificate identifier not found".to_string(),
                ))?;

            return Ok((certificate, identifier));
        }

        let ParsedCertificate {
            attributes,
            subject_common_name,
            ..
        } = self
            .certificate_validator
            .parse_pem_chain(&chain, CertificateValidationOptions::no_validation())
            .await?;

        if attributes.fingerprint != fingerprint {
            return Err(ServiceError::MappingError(format!(
                "Fingerprint {fingerprint} doesn't match provided certificate"
            )));
        }

        let now = OffsetDateTime::now_utc();
        let identifier_id = Uuid::new_v4().into();
        let name = format!("{role} {identifier_id}");

        let identifier = Identifier {
            id: identifier_id,
            created_date: now,
            last_modified: now,
            name: name.to_owned(),
            r#type: IdentifierType::Certificate,
            is_remote: true,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: organisation.to_owned(),
            did: None,
            key: None,
            certificates: None,
        };
        self.identifier_repository
            .create(identifier.clone())
            .await?;

        let certificate = Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            organisation_id: organisation.as_ref().map(|o| o.id),
            created_date: now,
            last_modified: now,
            expiry_date: attributes.not_after,
            name: subject_common_name.unwrap_or(name),
            chain,
            fingerprint,
            state: CertificateState::Active,
            key: None,
        };
        self.certificate_repository
            .create(certificate.clone())
            .await?;

        Ok((certificate, identifier))
    }

    pub(super) async fn get_or_create_key_identifier(
        &self,
        organisation: Option<&Organisation>,
        public_key: &PublicJwk,
        role: IdentifierRole,
    ) -> Result<(Key, Identifier), ServiceError> {
        let parsed_key = self.key_algorithm_provider.parse_jwk(public_key)?;
        let organisation_id = organisation.as_ref().map(|org| org.id);
        let now = OffsetDateTime::now_utc();

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
            .await?;

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
                .await?
                .values
                .into_iter()
                .next();

            if let Some(identifier) = identifier {
                return Ok((key, identifier));
            };

            key
        } else {
            let key_id = Uuid::new_v4().into();
            let key = Key {
                id: key_id,
                created_date: now,
                last_modified: now,
                name: format!("{role} {key_id}"),
                organisation: organisation.cloned(),
                public_key: parsed_key.key.public_key_as_raw(),
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: parsed_key.algorithm_type.to_string(),
            };

            self.key_repository.create_key(key.clone()).await?;
            key
        };

        let identifier_id = Uuid::new_v4().into();
        let identifier = Identifier {
            id: identifier_id,
            created_date: now,
            last_modified: now,
            name: format!("{role} {identifier_id}"),
            r#type: IdentifierType::Key,
            is_remote: true,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: organisation.cloned(),
            did: None,
            key: Some(key.clone()),
            certificates: None,
        };
        self.identifier_repository
            .create(identifier.clone())
            .await?;

        Ok((key, identifier))
    }
}
