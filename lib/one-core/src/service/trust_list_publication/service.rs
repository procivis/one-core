use std::sync::Arc;

use shared_types::{
    CertificateId, IdentifierId, KeyId, OrganisationId, TrustEntryId, TrustListPublicationId,
    TrustListPublisherId,
};

use crate::error::ContextWithErrorCode;
use crate::mapper::{list_response_into, list_response_try_into};
use crate::model::certificate::CertificateRelations;
use crate::model::identifier::{Identifier, IdentifierRelations};
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::trust_entry::{TrustEntry, TrustEntryListQuery, TrustEntryRelations};
use crate::model::trust_list_publication::{
    TrustListPublication, TrustListPublicationListQuery, TrustListPublicationRelations,
};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::provider::trust_list_publisher::{
    CreateTrustListRequest, TrustListPublisher, TrustListPublisherCapabilities,
};
use crate::service::trust_list_publication::TrustListPublicationService;
use crate::service::trust_list_publication::dto::{
    CreateTrustEntryRequestDTO, CreateTrustListPublicationRequestDTO, GetTrustEntryListResponseDTO,
    GetTrustListPublicationListResponseDTO, GetTrustListPublicationResponseDTO,
    UpdateTrustEntryRequestDTO,
};
use crate::service::trust_list_publication::error::TrustListPublicationServiceError;
use crate::util::key_selection::{KeySelection, SelectedKey};
use crate::validator::{
    throw_if_org_not_matching_session, throw_if_org_relation_not_matching_session,
};

impl TrustListPublicationService {
    pub async fn create_trust_list_publication(
        &self,
        request: CreateTrustListPublicationRequestDTO,
    ) -> Result<TrustListPublicationId, TrustListPublicationServiceError> {
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("validating organisation")?;

        let trust_list_publisher = self.fetch_trust_list_provider(&request.r#type).await?;
        validate_trust_list_role_capabilities(
            &request.role,
            trust_list_publisher.get_capabilities(),
        )?;

        let identifier = self.fetch_identifier(request.identifier_id).await?;
        validate_organisation_matches(&identifier, request.organisation_id)?;
        validate_publication_identifier_capabilities(
            &identifier,
            request.key_id,
            request.certificate_id,
            trust_list_publisher.get_capabilities(),
        )?;

        Ok(trust_list_publisher
            .create_trust_list(CreateTrustListRequest {
                name: request.name,
                role: request.role,
                organisation_id: request.organisation_id,
                identifier,
                key_id: request.key_id,
                certificate_id: request.certificate_id,
                params: request.params,
            })
            .await
            .error_while("creating trust list")?)
    }

    pub async fn delete_trust_list_publication(
        &self,
        id: TrustListPublicationId,
    ) -> Result<(), TrustListPublicationServiceError> {
        let trust_list = self.fetch_trust_list_publication(id).await?;
        throw_if_org_relation_not_matching_session(
            trust_list.organisation.as_ref(),
            &*self.session_provider,
        )
        .error_while("validating organisation")?;
        self.trust_list_publication_repository
            .delete(id)
            .await
            .error_while("deleting trust list publication")
            .map_err(Into::into)
    }

    pub async fn create_trust_entry(
        &self,
        list_id: TrustListPublicationId,
        request: CreateTrustEntryRequestDTO,
    ) -> Result<TrustEntryId, TrustListPublicationServiceError> {
        let trust_list_publication = self.fetch_trust_list_publication(list_id).await?;
        throw_if_org_not_matching_session(
            &trust_list_publication.organisation_id,
            &*self.session_provider,
        )
        .error_while("validating organisation")?;

        let trust_list_publisher = self
            .fetch_trust_list_provider(&trust_list_publication.r#type)
            .await?;
        let identifier = self.fetch_identifier(request.identifier_id).await?;
        validate_entry_identifier_capabilities(
            &identifier,
            trust_list_publisher.get_capabilities(),
        )?;
        validate_organisation_matches(&identifier, trust_list_publication.organisation_id)?;

        Ok(trust_list_publisher
            .add_entry(trust_list_publication, identifier, request.params)
            .await
            .error_while("adding entry to trust list")?)
    }

    pub async fn update_trust_entry(
        &self,
        list_id: TrustListPublicationId,
        entry_id: TrustEntryId,
        request: UpdateTrustEntryRequestDTO,
    ) -> Result<(), TrustListPublicationServiceError> {
        let trust_entry = self.fetch_trust_entry(entry_id).await?;
        validate_trust_entry_belongs_to_list(&trust_entry, list_id)?;

        let trust_list_publication = trust_entry.trust_list_publication()?;
        throw_if_org_not_matching_session(
            &trust_list_publication.organisation_id,
            &*self.session_provider,
        )
        .error_while("validating organisation")?;

        let trust_list_publisher = self
            .fetch_trust_list_provider(&trust_list_publication.r#type)
            .await?;

        Ok(trust_list_publisher
            .update_entry(trust_entry, request.status, request.params)
            .await
            .error_while("updating trust list entry")?)
    }

    pub async fn delete_trust_entry(
        &self,
        list_id: TrustListPublicationId,
        entry_id: TrustEntryId,
    ) -> Result<(), TrustListPublicationServiceError> {
        let trust_entry = self.fetch_trust_entry(entry_id).await?;
        validate_trust_entry_belongs_to_list(&trust_entry, list_id)?;

        let trust_list_publication = trust_entry.trust_list_publication()?;
        throw_if_org_relation_not_matching_session(
            trust_list_publication.organisation.as_ref(),
            &*self.session_provider,
        )
        .error_while("validating organisation")?;

        let trust_list_publisher = self
            .fetch_trust_list_provider(&trust_list_publication.r#type)
            .await?;

        Ok(trust_list_publisher
            .remove_entry(trust_entry)
            .await
            .error_while("removing entry from trust list")?)
    }

    pub async fn get_trust_list_publication(
        &self,
        id: TrustListPublicationId,
    ) -> Result<GetTrustListPublicationResponseDTO, TrustListPublicationServiceError> {
        let trust_list = self.fetch_trust_list_publication(id).await?;
        throw_if_org_relation_not_matching_session(
            trust_list.organisation.as_ref(),
            &*self.session_provider,
        )
        .error_while("validating organisation")?;
        trust_list.try_into()
    }

    pub async fn get_trust_list_publication_content(
        &self,
        id: TrustListPublicationId,
    ) -> Result<String, TrustListPublicationServiceError> {
        let trust_list = self.fetch_trust_list_publication(id).await?;
        throw_if_org_relation_not_matching_session(
            trust_list.organisation.as_ref(),
            &*self.session_provider,
        )
        .error_while("validating organisation")?;

        let provider = self.fetch_trust_list_provider(&trust_list.r#type).await?;
        let trust_list_content = provider
            .generate_trust_list_content(trust_list)
            .await
            .error_while("generating trust list content")?;
        Ok(trust_list_content)
    }

    pub async fn get_trust_list_publication_list(
        &self,
        organisation_id: OrganisationId,
        query: TrustListPublicationListQuery,
    ) -> Result<GetTrustListPublicationListResponseDTO, TrustListPublicationServiceError> {
        throw_if_org_not_matching_session(&organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        let trust_list_publication_list = self
            .trust_list_publication_repository
            .list(query)
            .await
            .error_while("getting trust list publications")?;
        Ok(list_response_into(trust_list_publication_list))
    }

    pub async fn get_trust_entry_list(
        &self,
        trust_list_publication_id: TrustListPublicationId,
        query: TrustEntryListQuery,
    ) -> Result<GetTrustEntryListResponseDTO, TrustListPublicationServiceError> {
        let trust_list_publication = self
            .fetch_trust_list_publication(trust_list_publication_id)
            .await?;
        throw_if_org_not_matching_session(
            &trust_list_publication.organisation_id,
            &*self.session_provider,
        )
        .error_while("validating organisation")?;
        let result = self
            .trust_entry_repository
            .list(trust_list_publication_id, query)
            .await
            .error_while("getting trust entries")?;
        list_response_try_into(result)
    }

    async fn fetch_trust_list_publication(
        &self,
        list_id: TrustListPublicationId,
    ) -> Result<TrustListPublication, TrustListPublicationServiceError> {
        self.trust_list_publication_repository
            .get(
                list_id,
                &TrustListPublicationRelations {
                    organisation: Some(OrganisationRelations::default()),
                    identifier: Some(IdentifierRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("fetching trust list publication")?
            .ok_or_else(|| TrustListPublicationServiceError::TrustListPublicationNotFound(list_id))
    }

    async fn fetch_trust_entry(
        &self,
        entry_id: TrustEntryId,
    ) -> Result<TrustEntry, TrustListPublicationServiceError> {
        self.trust_entry_repository
            .get(
                entry_id,
                &TrustEntryRelations {
                    trust_list_publication: Some(TrustListPublicationRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .error_while("fetching trust list publication")?
            .ok_or_else(|| TrustListPublicationServiceError::TrustEntryNotFound(entry_id))
    }

    async fn fetch_trust_list_provider(
        &self,
        trust_list_provider_id: &TrustListPublisherId,
    ) -> Result<Arc<dyn TrustListPublisher>, TrustListPublicationServiceError> {
        self.trust_list_publisher_provider
            .get(trust_list_provider_id)
            .ok_or_else(|| {
                TrustListPublicationServiceError::MissingTrustListProvider(
                    trust_list_provider_id.clone(),
                )
            })
    }

    async fn fetch_identifier(
        &self,
        identifier_id: IdentifierId,
    ) -> Result<Identifier, TrustListPublicationServiceError> {
        self.identifier_repository
            .get(
                identifier_id,
                &IdentifierRelations {
                    certificates: Some(CertificateRelations {
                        key: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    key: Some(KeyRelations::default()),
                    organisation: Some(OrganisationRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("fetching identifier")?
            .ok_or_else(|| TrustListPublicationServiceError::IdentifierNotFound(identifier_id))
    }
}

fn validate_trust_entry_belongs_to_list(
    trust_entry: &TrustEntry,
    trust_list_id: TrustListPublicationId,
) -> Result<(), TrustListPublicationServiceError> {
    if trust_entry.trust_list_publication_id != trust_list_id {
        return Err(TrustListPublicationServiceError::TrustEntryNotInList(
            trust_entry.id,
            trust_list_id,
        ));
    }
    Ok(())
}

fn validate_organisation_matches(
    identifier: &Identifier,
    organisation_id: OrganisationId,
) -> Result<(), TrustListPublicationServiceError> {
    let identifier_organisation_id = identifier
        .organisation
        .as_ref()
        .ok_or(TrustListPublicationServiceError::MappingError(
            "organisation is None".to_string(),
        ))?
        .id;

    if identifier_organisation_id != organisation_id {
        return Err(TrustListPublicationServiceError::OrganisationIdMismatch);
    }
    Ok(())
}

fn validate_trust_list_role_capabilities(
    role: &TrustListRoleEnum,
    capabilities: TrustListPublisherCapabilities,
) -> Result<(), TrustListPublicationServiceError> {
    if !capabilities.supported_roles.contains(role) {
        return Err(TrustListPublicationServiceError::InvalidTrustListRole(
            *role,
            capabilities.supported_roles,
        ));
    }
    Ok(())
}

fn validate_publication_identifier_capabilities(
    identifier: &Identifier,
    key_id: Option<KeyId>,
    certificate_id: Option<CertificateId>,
    capabilities: TrustListPublisherCapabilities,
) -> Result<(), TrustListPublicationServiceError> {
    let identifier_type = identifier.r#type.into();
    if !capabilities
        .publisher_identifier_types
        .contains(&identifier_type)
    {
        return Err(TrustListPublicationServiceError::InvalidIdentifierType(
            identifier_type,
            capabilities.publisher_identifier_types,
        ));
    }

    let selected = identifier
        .select_key(KeySelection {
            key: key_id,
            certificate: certificate_id,
            ..Default::default()
        })
        .error_while("selecting key")?;

    let SelectedKey::Certificate { key, .. } = &selected else {
        return Err(TrustListPublicationServiceError::InvalidSelectedKey);
    };

    let key_algorithm_type = key.key_algorithm_type().ok_or_else(|| {
        TrustListPublicationServiceError::UnknownKeyAlgorithm(key.key_type.clone())
    })?;

    if !capabilities.key_algorithms.contains(&key_algorithm_type) {
        return Err(TrustListPublicationServiceError::InvalidKeyType(
            key_algorithm_type,
            capabilities.key_algorithms,
        ));
    };
    Ok(())
}

fn validate_entry_identifier_capabilities(
    identifier: &Identifier,
    capabilities: TrustListPublisherCapabilities,
) -> Result<(), TrustListPublicationServiceError> {
    let identifier_type = identifier.r#type.into();
    if !capabilities
        .entry_identifier_types
        .contains(&identifier_type)
    {
        return Err(TrustListPublicationServiceError::InvalidIdentifierType(
            identifier_type,
            capabilities.entry_identifier_types,
        ));
    }
    Ok(())
}

trait TrustEntryExt {
    fn trust_list_publication(
        &self,
    ) -> Result<&TrustListPublication, TrustListPublicationServiceError>;
}

impl TrustEntryExt for TrustEntry {
    fn trust_list_publication(
        &self,
    ) -> Result<&TrustListPublication, TrustListPublicationServiceError> {
        self.trust_list_publication.as_ref().ok_or_else(|| {
            TrustListPublicationServiceError::MappingError(
                "trust_list_publication is None".to_string(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mockall::predicate;
    use shared_types::TrustListPublisherId;
    use similar_asserts::assert_eq;
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use super::*;
    use crate::model::certificate::{Certificate, CertificateState};
    use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
    use crate::model::key::Key;
    use crate::model::organisation::Organisation;
    use crate::model::trust_entry::TrustEntryStatusEnum;
    use crate::model::trust_list_role::TrustListRoleEnum;
    use crate::proto::session_provider::MockSessionProvider;
    use crate::provider::trust_list_publisher::provider::MockTrustListPublisherProvider;
    use crate::provider::trust_list_publisher::{
        MockTrustListPublisher, TrustListPublisherCapabilities,
    };
    use crate::repository::identifier_repository::MockIdentifierRepository;
    use crate::repository::trust_entry_repository::MockTrustEntryRepository;
    use crate::repository::trust_list_publication_repository::MockTrustListPublicationRepository;

    #[tokio::test]
    async fn test_create_trust_list_publication_identifier_matches_capabilities() {
        // given
        let mut identifier_repository = MockIdentifierRepository::default();
        let mut publisher_provider = MockTrustListPublisherProvider::default();
        let mut trust_list_publisher = MockTrustListPublisher::default();
        let mut session_provider = MockSessionProvider::default();

        let organisation_id = Uuid::new_v4().into();
        let identifier_id = Uuid::new_v4().into();
        let publisher_id: TrustListPublisherId = "LOTE".into();
        let trust_list_publication_id = Uuid::new_v4().into();
        let now = OffsetDateTime::now_utc();
        let identifier = Identifier {
            id: identifier_id,
            created_date: now,
            last_modified: now,
            name: "TestIdentifier".to_string(),
            r#type: IdentifierType::Certificate,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: Some(Organisation {
                id: organisation_id,
                name: "TestOrganisation".to_string(),
                created_date: now,
                last_modified: now,
                deactivated_at: None,
                wallet_provider: None,
                wallet_provider_issuer: None,
            }),
            did: None,
            key: None,
            certificates: Some(vec![Certificate {
                id: Uuid::new_v4().into(),
                identifier_id,
                organisation_id: Some(organisation_id),
                created_date: now,
                last_modified: now,
                expiry_date: now + Duration::days(2),
                name: "testCertifcate".to_string(),
                chain: "".to_string(),
                fingerprint: "".to_string(),
                state: CertificateState::Active,
                key: Some(Key {
                    id: Uuid::new_v4().into(),
                    created_date: now,
                    last_modified: now,
                    public_key: vec![],
                    name: "".to_string(),
                    key_reference: None,
                    storage_type: "".to_string(),
                    key_type: "EDDSA".to_string(),
                    organisation: None,
                }),
            }]),
        };

        identifier_repository
            .expect_get()
            .with(predicate::eq(identifier_id), predicate::always())
            .returning(move |_, _| Ok(Some(identifier.clone())));

        trust_list_publisher
            .expect_get_capabilities()
            .returning(|| TrustListPublisherCapabilities {
                key_algorithms: vec![crate::config::core_config::KeyAlgorithmType::Eddsa],
                publisher_identifier_types: vec![
                    crate::config::core_config::IdentifierType::Certificate,
                ],
                entry_identifier_types: vec![],
                supported_roles: vec![TrustListRoleEnum::PidProvider],
            });

        trust_list_publisher
            .expect_create_trust_list()
            .returning(move |_| Ok(trust_list_publication_id));

        let trust_list_publisher = Arc::new(trust_list_publisher);

        publisher_provider
            .expect_get()
            .with(predicate::eq(publisher_id.clone()))
            .return_once(move |_| Some(trust_list_publisher));

        session_provider.expect_session().returning(|| None);

        let service = TrustListPublicationService::new(
            Arc::new(identifier_repository),
            Arc::new(MockTrustListPublicationRepository::default()),
            Arc::new(MockTrustEntryRepository::default()),
            Arc::new(session_provider),
            Arc::new(publisher_provider),
        );

        // when
        let result = service
            .create_trust_list_publication(CreateTrustListPublicationRequestDTO {
                r#type: publisher_id,
                organisation_id,
                identifier_id,
                key_id: None,
                certificate_id: None,
                name: "testName".to_string(),
                role: TrustListRoleEnum::PidProvider,
                params: Default::default(),
            })
            .await;

        // then
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_entry_identifier_capabilities_success() {
        // given
        let identifier = create_test_key_identifier("EDDSA");
        let capabilities = TrustListPublisherCapabilities {
            supported_roles: vec![],
            key_algorithms: vec![],
            publisher_identifier_types: vec![],
            entry_identifier_types: vec![crate::config::core_config::IdentifierType::Key],
        };

        // when
        let result = validate_entry_identifier_capabilities(&identifier, capabilities);

        // then
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_entry_identifier_capabilities_invalid_type() {
        // given
        let identifier = create_test_key_identifier("EDDSA");
        let capabilities = TrustListPublisherCapabilities {
            supported_roles: vec![],
            key_algorithms: vec![],
            publisher_identifier_types: vec![],
            entry_identifier_types: vec![crate::config::core_config::IdentifierType::Did],
        };

        // when
        let result = validate_entry_identifier_capabilities(&identifier, capabilities);

        // then
        assert!(result.is_err());
        match result {
            Err(TrustListPublicationServiceError::InvalidIdentifierType(
                identifier_type,
                supported_types,
            )) => {
                assert_eq!(
                    identifier_type,
                    crate::config::core_config::IdentifierType::Key
                );
                assert_eq!(
                    supported_types,
                    vec![crate::config::core_config::IdentifierType::Did]
                );
            }
            _ => panic!("Expected InvalidIdentifierType error"),
        }
    }

    #[test]
    fn test_validate_entry_identifier_capabilities_multiple_supported_types() {
        // given
        let identifier = create_test_did_identifier();
        let capabilities = TrustListPublisherCapabilities {
            supported_roles: vec![],
            key_algorithms: vec![],
            publisher_identifier_types: vec![],
            entry_identifier_types: vec![
                crate::config::core_config::IdentifierType::Key,
                crate::config::core_config::IdentifierType::Did,
            ],
        };

        // when
        let result = validate_entry_identifier_capabilities(&identifier, capabilities);

        // then
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_entry_identifier_capabilities_empty_supported_types() {
        // given
        let identifier = create_test_key_identifier("EDDSA");
        let capabilities = TrustListPublisherCapabilities {
            supported_roles: vec![],
            key_algorithms: vec![],
            publisher_identifier_types: vec![],
            entry_identifier_types: vec![],
        };

        // when
        let result = validate_entry_identifier_capabilities(&identifier, capabilities);

        // then
        assert!(result.is_err());
        match result {
            Err(TrustListPublicationServiceError::InvalidIdentifierType(
                identifier_type,
                supported_types,
            )) => {
                assert_eq!(
                    identifier_type,
                    crate::config::core_config::IdentifierType::Key
                );
                assert!(supported_types.is_empty());
            }
            _ => panic!("Expected InvalidIdentifierType error"),
        }
    }

    #[test]
    fn test_validate_publication_identifier_capabilities_success() {
        // given
        let identifier = create_test_certificate_identifier("EDDSA");
        let certificate_id = identifier.certificates.as_ref().unwrap()[0].id;
        let capabilities = TrustListPublisherCapabilities {
            supported_roles: vec![],
            key_algorithms: vec![crate::config::core_config::KeyAlgorithmType::Eddsa],
            publisher_identifier_types: vec![
                crate::config::core_config::IdentifierType::Certificate,
            ],
            entry_identifier_types: vec![],
        };

        // when
        let result = validate_publication_identifier_capabilities(
            &identifier,
            None,
            Some(certificate_id),
            capabilities,
        );

        // then
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_publication_identifier_capabilities_invalid_identifier_type() {
        // given
        let identifier = create_test_key_identifier("EDDSA");
        let capabilities = TrustListPublisherCapabilities {
            supported_roles: vec![],
            key_algorithms: vec![crate::config::core_config::KeyAlgorithmType::Eddsa],
            publisher_identifier_types: vec![crate::config::core_config::IdentifierType::Did],
            entry_identifier_types: vec![],
        };

        // when
        let result =
            validate_publication_identifier_capabilities(&identifier, None, None, capabilities);

        // then
        assert!(result.is_err());
        match result {
            Err(TrustListPublicationServiceError::InvalidIdentifierType(
                identifier_type,
                supported_types,
            )) => {
                assert_eq!(
                    identifier_type,
                    crate::config::core_config::IdentifierType::Key
                );
                assert_eq!(
                    supported_types,
                    vec![crate::config::core_config::IdentifierType::Did]
                );
            }
            _ => panic!("Expected InvalidIdentifierType error"),
        }
    }

    #[test]
    fn test_validate_publication_identifier_capabilities_missing_key() {
        // given
        let mut identifier = create_test_key_identifier("EDDSA");
        identifier.key = None;
        let key_id = Uuid::new_v4().into();
        let capabilities = TrustListPublisherCapabilities {
            supported_roles: vec![],
            key_algorithms: vec![crate::config::core_config::KeyAlgorithmType::Eddsa],
            publisher_identifier_types: vec![crate::config::core_config::IdentifierType::Key],
            entry_identifier_types: vec![],
        };

        // when
        let result = validate_publication_identifier_capabilities(
            &identifier,
            Some(key_id),
            None,
            capabilities,
        );

        // then
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_publication_identifier_capabilities_missing_certificate() {
        // given
        let mut identifier = create_test_certificate_identifier("EDDSA");
        identifier.certificates = None;
        let certificate_id = Uuid::new_v4().into();
        let capabilities = TrustListPublisherCapabilities {
            supported_roles: vec![],
            key_algorithms: vec![crate::config::core_config::KeyAlgorithmType::Eddsa],
            publisher_identifier_types: vec![
                crate::config::core_config::IdentifierType::Certificate,
            ],
            entry_identifier_types: vec![],
        };

        // when
        let result = validate_publication_identifier_capabilities(
            &identifier,
            None,
            Some(certificate_id),
            capabilities,
        );

        // then
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_publication_identifier_capabilities_invalid_selected_key_type() {
        // given
        let identifier = create_test_key_identifier("EDDSA");
        let key_id = identifier.key.as_ref().unwrap().id;

        let capabilities = TrustListPublisherCapabilities {
            supported_roles: vec![],
            key_algorithms: vec![crate::config::core_config::KeyAlgorithmType::Eddsa],
            publisher_identifier_types: vec![crate::config::core_config::IdentifierType::Key],
            entry_identifier_types: vec![],
        };

        // when
        let result = validate_publication_identifier_capabilities(
            &identifier,
            Some(key_id),
            None,
            capabilities,
        );

        // then
        assert!(result.is_err());
        match result {
            Err(TrustListPublicationServiceError::InvalidSelectedKey) => {}
            Err(e) => panic!("Expected InvalidSelectedKey error, got: {:?}", e),
            _ => panic!("Expected InvalidSelectedKey error"),
        }
    }

    #[test]
    fn test_validate_publication_identifier_capabilities_unknown_key_algorithm() {
        // given
        let identifier = create_test_certificate_identifier("UNKNOWN_ALGO");
        let certificate_id = identifier.certificates.as_ref().unwrap()[0].id;
        let capabilities = TrustListPublisherCapabilities {
            supported_roles: vec![],
            key_algorithms: vec![crate::config::core_config::KeyAlgorithmType::Eddsa],
            publisher_identifier_types: vec![
                crate::config::core_config::IdentifierType::Certificate,
            ],
            entry_identifier_types: vec![],
        };

        // when
        let result = validate_publication_identifier_capabilities(
            &identifier,
            None,
            Some(certificate_id),
            capabilities,
        );

        // then
        assert!(result.is_err());
        match result {
            Err(TrustListPublicationServiceError::UnknownKeyAlgorithm(key_type)) => {
                assert_eq!(key_type, "UNKNOWN_ALGO");
            }
            _ => panic!("Expected UnknownKeyAlgorithm error"),
        }
    }

    #[test]
    fn test_validate_publication_identifier_capabilities_invalid_key_algorithm() {
        // given
        let identifier = create_test_certificate_identifier("ECDSA");
        let certificate_id = identifier.certificates.as_ref().unwrap()[0].id;
        let capabilities = TrustListPublisherCapabilities {
            supported_roles: vec![],
            key_algorithms: vec![crate::config::core_config::KeyAlgorithmType::Eddsa],
            publisher_identifier_types: vec![
                crate::config::core_config::IdentifierType::Certificate,
            ],
            entry_identifier_types: vec![],
        };

        // when
        let result = validate_publication_identifier_capabilities(
            &identifier,
            None,
            Some(certificate_id),
            capabilities,
        );

        // then
        match result {
            Err(TrustListPublicationServiceError::InvalidKeyType(
                key_algorithm,
                supported_algorithms,
            )) => {
                assert_eq!(
                    key_algorithm,
                    crate::config::core_config::KeyAlgorithmType::Ecdsa
                );
                assert_eq!(
                    supported_algorithms,
                    vec![crate::config::core_config::KeyAlgorithmType::Eddsa]
                );
            }
            Err(e) => panic!("Expected InvalidKeyType error, got: {:?}", e),
            _ => panic!("Expected InvalidKeyType error, got Ok"),
        }
    }

    #[test]
    fn test_validate_trust_entry_belongs_to_list_success() {
        // given
        let trust_list_id = Uuid::new_v4().into();
        let trust_entry = create_test_trust_entry(trust_list_id);

        // when
        let result = validate_trust_entry_belongs_to_list(&trust_entry, trust_list_id);

        // then
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_trust_entry_belongs_to_list_mismatch() {
        // given
        let trust_list_id = Uuid::new_v4().into();
        let different_list_id = Uuid::new_v4().into();
        let trust_entry = create_test_trust_entry(different_list_id);

        // when
        let result = validate_trust_entry_belongs_to_list(&trust_entry, trust_list_id);

        // then
        assert!(result.is_err());
        match result {
            Err(TrustListPublicationServiceError::TrustEntryNotInList(entry_id, list_id)) => {
                assert_eq!(entry_id, trust_entry.id);
                assert_eq!(list_id, trust_list_id);
            }
            _ => panic!("Expected TrustEntryNotInList error"),
        }
    }

    fn create_test_trust_entry(trust_list_publication_id: TrustListPublicationId) -> TrustEntry {
        let now = OffsetDateTime::now_utc();
        TrustEntry {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            trust_list_publication_id,
            identifier_id: Uuid::new_v4().into(),
            status: TrustEntryStatusEnum::Active,
            metadata: Default::default(),
            trust_list_publication: None,
            identifier: None,
        }
    }

    fn create_test_key_identifier(key_type: &str) -> Identifier {
        let now = OffsetDateTime::now_utc();
        Identifier {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            name: "TestIdentifier".to_string(),
            r#type: IdentifierType::Key,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: None,
            key: Some(create_test_key(key_type)),
            certificates: None,
        }
    }

    fn create_test_did_identifier() -> Identifier {
        let now = OffsetDateTime::now_utc();
        Identifier {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            name: "TestIdentifier".to_string(),
            r#type: IdentifierType::Did,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: None,
            key: None,
            certificates: None,
        }
    }

    fn create_test_key(key_type: &str) -> Key {
        let now = OffsetDateTime::now_utc();
        Key {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            public_key: vec![1, 2, 3],
            name: "TestKey".to_string(),
            key_reference: None,
            storage_type: "INTERNAL".to_string(),
            key_type: key_type.to_string(),
            organisation: None,
        }
    }

    fn create_test_certificate_identifier(key_type: &str) -> Identifier {
        let now = OffsetDateTime::now_utc();
        let key = create_test_key(key_type);
        let identifier_id = Uuid::new_v4().into();
        let certificate = crate::model::certificate::Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            organisation_id: None,
            created_date: now,
            last_modified: now,
            expiry_date: now + Duration::days(1),
            name: "TestCertificate".to_string(),
            chain: "".to_string(),
            fingerprint: "".to_string(),
            key: Some(key),
            state: CertificateState::Active,
        };

        Identifier {
            id: identifier_id,
            created_date: now,
            last_modified: now,
            name: "TestIdentifier".to_string(),
            r#type: IdentifierType::Certificate,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: None,
            key: None,
            certificates: Some(vec![certificate]),
        }
    }
}
