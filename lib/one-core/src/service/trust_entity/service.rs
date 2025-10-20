use std::collections::HashMap;

use shared_types::{DidId, DidValue, IdentifierId, TrustAnchorId, TrustEntityId, TrustEntityKey};
use uuid::Uuid;

use super::TrustEntityService;
use super::dto::{
    CreateTrustEntityFromDidPublisherRequestDTO, CreateTrustEntityParamsDTO,
    CreateTrustEntityRequestDTO, CreateTrustEntityTypeDTO, GetTrustEntitiesResponseDTO,
    GetTrustEntityResponseDTO, ListTrustEntitiesQueryDTO, ResolveTrustEntitiesRequestDTO,
    ResolveTrustEntitiesResponseDTO, ResolveTrustEntityRequestDTO,
    TrustEntityCertificateResponseDTO, TrustEntityContent, UpdateTrustEntityFromDidRequestDTO,
};
use super::mapper::{
    trust_entity_certificate_from_x509, trust_entity_from_did_request,
    trust_entity_from_identifier_and_anchor, trust_entity_from_partial_and_did_and_anchor,
    trust_entity_from_request, update_request_from_dto,
};
use crate::config::core_config::TrustManagementType::SimpleTrustList;
use crate::mapper::x509::pem_chain_to_authority_key_identifiers;
use crate::mapper::{IdentifierRole, get_or_create_did_and_identifier};
use crate::model::certificate::{Certificate, CertificateRelations, CertificateState};
use crate::model::did::{DidRelations, DidType};
use crate::model::identifier::{Identifier, IdentifierRelations, IdentifierType};
use crate::model::list_filter::{ListFilterCondition, ListFilterValue, StringMatch};
use crate::model::list_query::ListPagination;
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::trust_anchor::{TrustAnchor, TrustAnchorRelations};
use crate::model::trust_entity::{
    TrustEntity, TrustEntityRelations, TrustEntityRole, TrustEntityType,
};
use crate::proto::certificate_validator::{
    CertSelection, CertificateValidationOptions, CrlMode, ParsedCertificate,
};
use crate::provider::trust_management::model::TrustEntityByEntityKey;
use crate::provider::trust_management::{TrustEntityKeyBatch, TrustOperation};
use crate::repository::error::DataLayerError;
use crate::service::error::BusinessLogicError::IdentifierCertificateIdMismatch;
use crate::service::error::ServiceError::MappingError;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::trust_anchor::dto::{ListTrustAnchorsQueryDTO, TrustAnchorFilterValue};
use crate::service::trust_entity::dto::{
    ResolvedIdentifierTrustEntityResponseDTO, UpdateTrustEntityActionFromDidRequestDTO,
};
use crate::service::trust_entity::mapper::get_detail_trust_entity_response;
use crate::util::bearer_token::validate_bearer_token;

impl TrustEntityService {
    pub async fn create_trust_entity(
        &self,
        request: CreateTrustEntityRequestDTO,
    ) -> Result<TrustEntityId, ServiceError> {
        let trust_anchor = self
            .trust_anchor_repository
            .get(request.trust_anchor_id)
            .await?
            .ok_or(EntityNotFoundError::TrustAnchor(request.trust_anchor_id))?;

        if !trust_anchor.is_publisher {
            return Err(BusinessLogicError::TrustAnchorMustBePublish.into());
        }

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &Default::default())
            .await?
            .ok_or(EntityNotFoundError::Organisation(request.organisation_id))?;

        if organisation.deactivated_at.is_some() {
            return Err(
                BusinessLogicError::OrganisationIsDeactivated(request.organisation_id).into(),
            );
        }

        let (entity_type, entity_params) = request.try_into()?;

        let trust_entity = match entity_type {
            CreateTrustEntityTypeDTO::Identifier(identifier_id) => {
                self.trust_entity_from_identifier_params(
                    identifier_id,
                    entity_params,
                    trust_anchor,
                    organisation,
                )
                .await?
            }
            CreateTrustEntityTypeDTO::Did(did_id) => {
                self.trust_entity_from_did_params(did_id, entity_params, trust_anchor, organisation)
                    .await?
            }
            CreateTrustEntityTypeDTO::Certificate(certificate) => {
                self.trust_entity_from_certificate_params(
                    certificate,
                    entity_params,
                    trust_anchor,
                    organisation,
                )
                .await?
            }
        };

        self.trust_entity_repository
            .create(trust_entity)
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => {
                    BusinessLogicError::TrustEntityAlreadyPresent.into()
                }
                err => err.into(),
            })
    }

    async fn trust_entity_from_certificate_params(
        &self,
        content: TrustEntityContent,
        params: CreateTrustEntityParamsDTO,
        trust_anchor: TrustAnchor,
        organisation: Organisation,
    ) -> Result<TrustEntity, ServiceError> {
        let certificate = self
            .certificate_validator
            .parse_pem_chain(
                &content,
                CertificateValidationOptions::full_validation(None),
            )
            .await?;

        let entity_key = TrustEntityKey::try_from(&certificate)?;

        Ok(trust_entity_from_request(
            entity_key,
            organisation,
            Some(content),
            TrustEntityType::CertificateAuthority,
            params,
            trust_anchor,
        ))
    }

    async fn trust_entity_from_identifier_params(
        &self,
        identifier_id: IdentifierId,
        params: CreateTrustEntityParamsDTO,
        trust_anchor: TrustAnchor,
        organisation: Organisation,
    ) -> Result<TrustEntity, ServiceError> {
        let identifier = self
            .identifier_repository
            .get(
                identifier_id,
                &IdentifierRelations {
                    organisation: None,
                    did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    key: None,
                    certificates: None,
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Identifier(identifier_id))?;

        let Some(did) = identifier.did else {
            return Err(BusinessLogicError::IncompatibleIdentifierType {
                reason: "trust entity only supports did identifiers".to_string(),
            }
            .into());
        };

        if did.did_type == DidType::Remote {
            return Err(BusinessLogicError::IncompatibleDidType {
                reason: "Only local DIDs allowed".to_string(),
            }
            .into());
        }

        let entity_key = (&did.did).into();

        Ok(trust_entity_from_request(
            entity_key,
            organisation,
            None,
            TrustEntityType::Did,
            params,
            trust_anchor,
        ))
    }

    async fn trust_entity_from_did_params(
        &self,
        did_id: DidId,
        params: CreateTrustEntityParamsDTO,
        trust_anchor: TrustAnchor,
        organisation: Organisation,
    ) -> Result<TrustEntity, ServiceError> {
        let did = self
            .did_repository
            .get_did(
                &did_id,
                &DidRelations {
                    organisation: Some(OrganisationRelations {}),
                    keys: None,
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Did(did_id))?;

        if did.did_type == DidType::Remote {
            return Err(BusinessLogicError::IncompatibleDidType {
                reason: "Only local DIDs allowed".to_string(),
            }
            .into());
        }

        let entity_key = (&did.did).into();

        Ok(trust_entity_from_request(
            entity_key,
            organisation,
            None,
            TrustEntityType::Did,
            params,
            trust_anchor,
        ))
    }

    pub async fn publisher_create_trust_entity_for_did(
        &self,
        request: CreateTrustEntityFromDidPublisherRequestDTO,
        bearer_token: &str,
    ) -> Result<TrustEntityId, ServiceError> {
        let did_value = request.did.clone();

        self.validate_bearer_token(&did_value, bearer_token).await?;

        let trust_anchor = self.get_trust_anchor(request.trust_anchor_id, true).await?;

        if !trust_anchor.is_publisher {
            return Err(BusinessLogicError::TrustAnchorMustBePublish.into());
        }

        let trust = self
            .trust_provider
            .get(&trust_anchor.r#type)
            .ok_or_else(|| MissingProviderError::TrustManager(trust_anchor.r#type.clone()))?;

        if !trust
            .get_capabilities()
            .operations
            .contains(&TrustOperation::Publish)
        {
            return Err(BusinessLogicError::TrustAnchorIsDisabled.into());
        }

        if self
            .trust_entity_repository
            .get_by_entity_key(&(&did_value).into())
            .await?
            .is_some()
        {
            return Err(BusinessLogicError::TrustEntityAlreadyPresent.into());
        }

        let did_role = match request.role {
            TrustEntityRole::Issuer => IdentifierRole::Issuer,
            TrustEntityRole::Verifier => IdentifierRole::Verifier,
            TrustEntityRole::Both => IdentifierRole::Issuer,
        };

        // See: ONE-6304, we expect the remote DID to be available at a later stage
        let (_did, _identifier) = get_or_create_did_and_identifier(
            &*self.did_method_provider,
            &*self.did_repository,
            &*self.identifier_repository,
            &None,
            &did_value,
            did_role,
        )
        .await?;

        let entity = trust_entity_from_did_request(request, trust_anchor.clone(), did_value);

        trust.publish_entity(&trust_anchor, &entity).await;

        self.trust_entity_repository
            .create(entity)
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => {
                    BusinessLogicError::TrustEntityAlreadyPresent.into()
                }
                err => err.into(),
            })
    }

    pub async fn get_trust_entity(
        &self,
        id: TrustEntityId,
    ) -> Result<GetTrustEntityResponseDTO, ServiceError> {
        let trust_entity = self
            .trust_entity_repository
            .get(
                id,
                &TrustEntityRelations {
                    trust_anchor: Some(TrustAnchorRelations::default()),
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::TrustEntity(id))?;

        let (mut identifier, content) = match &trust_entity.r#type {
            TrustEntityType::Did => {
                let did_value = DidValue::from_did_url(&trust_entity.entity_key).map_err(|_| {
                    MappingError("invalid trust_entity.entity_key for type did".to_string())
                })?;
                let organisation_id = trust_entity.organisation.as_ref().map(|o| o.id);

                let did = self
                    .did_repository
                    .get_did_by_value(&did_value, Some(organisation_id), &DidRelations::default())
                    .await?
                    .ok_or(ServiceError::EntityNotFound(EntityNotFoundError::DidValue(
                        did_value,
                    )))?;

                let mut identifier = self
                    .identifier_repository
                    .get_from_did_id(did.id, &IdentifierRelations::default())
                    .await?
                    .ok_or(ServiceError::EntityNotFound(
                        EntityNotFoundError::IdentifierByDidId(did.id),
                    ))?;

                identifier.did = Some(did);
                (Some(identifier), None)
            }
            TrustEntityType::CertificateAuthority => {
                let pem_chain = trust_entity.content.as_ref().ok_or(MappingError(
                    "missing trust_entity.content for type certificate".to_string(),
                ))?;

                let unchecked_certificate = async || {
                    self.certificate_validator
                        .parse_pem_chain(pem_chain, CertificateValidationOptions::no_validation())
                        .await
                };

                let (
                    state,
                    ParsedCertificate {
                        attributes,
                        public_key,
                        subject_common_name,
                        ..
                    },
                ) = match self
                    .certificate_validator
                    .parse_pem_chain(
                        pem_chain,
                        CertificateValidationOptions {
                            require_root_termination: false,
                            integrity_check: false,
                            validity_check: Some(CrlMode::X509),
                            required_leaf_cert_key_usage: Default::default(),
                            leaf_only_extensions: Default::default(),
                        },
                    )
                    .await
                {
                    Ok(parsed) => (CertificateState::Active, parsed),
                    Err(ServiceError::Validation(ValidationError::CertificateNotYetValid)) => (
                        CertificateState::NotYetActive,
                        unchecked_certificate().await?,
                    ),
                    Err(ServiceError::Validation(ValidationError::CertificateExpired)) => {
                        (CertificateState::Expired, unchecked_certificate().await?)
                    }
                    Err(ServiceError::Validation(ValidationError::CertificateRevoked)) => {
                        (CertificateState::Revoked, unchecked_certificate().await?)
                    }
                    Err(err) => {
                        return Err(err);
                    }
                };

                let public_key = hex::encode(public_key.public_key_as_raw());

                (
                    None,
                    Some(trust_entity_certificate_from_x509(
                        state,
                        public_key,
                        subject_common_name,
                        attributes,
                    )),
                )
            }
        };

        get_detail_trust_entity_response(
            trust_entity,
            identifier.as_mut().and_then(|i| i.did.take()),
            identifier,
            content,
        )
    }

    pub async fn publisher_get_trust_entity_for_did(
        &self,
        did_value: DidValue,
        bearer_token: &str,
    ) -> Result<GetTrustEntityResponseDTO, ServiceError> {
        self.validate_bearer_token(&did_value, bearer_token).await?;

        let did = self
            .did_repository
            .get_did_by_value(
                &did_value,
                Some(None),
                &DidRelations {
                    organisation: Some(OrganisationRelations {}),
                    keys: None,
                },
            )
            .await?
            .ok_or(ServiceError::ValidationError("unknown did".to_string()))?;
        let entity_key: TrustEntityKey = did_value.into();

        let result = self
            .trust_entity_repository
            .get_by_entity_key(&entity_key)
            .await?
            .ok_or(ServiceError::EntityNotFound(
                EntityNotFoundError::TrustEntityByEntityKey(entity_key),
            ))?;

        get_detail_trust_entity_response(result, Some(did), None, None)
    }

    pub async fn list_trust_entities(
        &self,
        filters: ListTrustEntitiesQueryDTO,
    ) -> Result<GetTrustEntitiesResponseDTO, ServiceError> {
        self.trust_entity_repository
            .list(filters)
            .await
            .map_err(Into::into)
    }

    async fn update_trust_entity(
        &self,
        entity: TrustEntity,
        request: UpdateTrustEntityFromDidRequestDTO,
    ) -> Result<(), ServiceError> {
        if let Some(content) = &request.content {
            match entity.r#type {
                TrustEntityType::Did => return Err(ValidationError::TrustEntityTypeInvalid.into()),
                TrustEntityType::CertificateAuthority => {
                    let cert = self
                        .certificate_validator
                        .parse_pem_chain(
                            content,
                            CertificateValidationOptions::full_validation(None),
                        )
                        .await?;
                    if entity.entity_key != TrustEntityKey::try_from(&cert)? {
                        return Err(
                            ValidationError::TrustEntitySubjectKeyIdentifierDoesNotMatch.into()
                        );
                    }
                }
            }
        }

        let request = update_request_from_dto(entity.state, request)?;

        self.trust_entity_repository
            .update(entity.id, request)
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => {
                    ServiceError::BusinessLogic(BusinessLogicError::TrustEntityAlreadyPresent)
                }
                err => err.into(),
            })?;

        Ok(())
    }

    // PUBLISHER or NON-PUBLISHER
    pub async fn update_trust_entity_by_trust_entity(
        &self,
        id: TrustEntityId,
        update_request: UpdateTrustEntityFromDidRequestDTO,
    ) -> Result<(), ServiceError> {
        let entity = self
            .trust_entity_repository
            .get(
                id,
                &TrustEntityRelations {
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::TrustEntity(id))?;

        self.update_trust_entity(entity, update_request).await?;

        Ok(())
    }

    // NON-PUBLISHER
    pub async fn update_trust_entity_by_did(
        &self,
        did_value: DidValue,
        request: UpdateTrustEntityFromDidRequestDTO,
        bearer_token: &str,
    ) -> Result<(), ServiceError> {
        self.validate_bearer_token(&did_value, bearer_token).await?;

        // only allowed to withdraw/activate
        if matches!(
            request.action,
            Some(
                UpdateTrustEntityActionFromDidRequestDTO::Remove
                    | UpdateTrustEntityActionFromDidRequestDTO::AdminActivate,
            )
        ) {
            return Err(ValidationError::InvalidUpdateRequest.into());
        }

        let did = self
            .did_repository
            .get_did_by_value(&did_value, Some(None), &DidRelations::default())
            .await?
            .ok_or(EntityNotFoundError::DidValue(did_value))?;

        let Some(entity) = self
            .trust_entity_repository
            .get_by_entity_key(&did.did.into())
            .await?
        else {
            return Err(BusinessLogicError::TrustEntityHasDuplicates.into());
        };

        self.update_trust_entity(entity.clone(), request).await?;

        Ok(())
    }

    async fn validate_bearer_token(
        &self,
        did_value: &DidValue,
        bearer_token: &str,
    ) -> Result<(), ServiceError> {
        let jwt = validate_bearer_token(
            bearer_token,
            self.did_method_provider.clone(),
            self.key_algorithm_provider.clone(),
            self.certificate_validator.clone(),
        )
        .await?;

        let token_issuer = jwt.payload.issuer.ok_or(ValidationError::Forbidden)?;

        if token_issuer != did_value.as_str() {
            return Err(ValidationError::Forbidden.into());
        }

        Ok(())
    }

    pub(super) async fn get_trust_anchor(
        &self,
        trust_anchor_id: Option<TrustAnchorId>,
        is_publisher: bool,
    ) -> Result<TrustAnchor, ServiceError> {
        match trust_anchor_id {
            None => {
                let anchors = self
                    .trust_anchor_repository
                    .list(ListTrustAnchorsQueryDTO {
                        pagination: Some(ListPagination {
                            page: 0,
                            page_size: 2,
                        }),
                        sorting: None,
                        filtering: Some(ListFilterCondition::Value(
                            TrustAnchorFilterValue::IsPublisher(is_publisher),
                        )),
                        include: None,
                    })
                    .await?;
                if anchors.values.len() > 1 {
                    return Err(BusinessLogicError::MultipleMatchingTrustAnchors.into());
                }
                let trust_anchor = anchors.values.first().ok_or(ServiceError::EntityNotFound(
                    EntityNotFoundError::TrustAnchor(Uuid::default().into()),
                ))?;
                Ok(trust_anchor.clone().into())
            }
            Some(trust_anchor_id) => {
                Ok(self
                    .trust_anchor_repository
                    .get(trust_anchor_id)
                    .await?
                    .ok_or(EntityNotFoundError::TrustAnchor(trust_anchor_id))?)
            }
        }
    }

    pub async fn lookup_did(
        &self,
        did_id: DidId,
    ) -> Result<GetTrustEntityResponseDTO, ServiceError> {
        let trust_anchor_list = self
            .trust_anchor_repository
            .list(ListTrustAnchorsQueryDTO {
                pagination: None,
                sorting: None,
                filtering: Some(
                    TrustAnchorFilterValue::Type(StringMatch::equals(SimpleTrustList.to_string()))
                        .condition(),
                ),
                include: None,
            })
            .await?;

        for trust_anchor in trust_anchor_list.values.into_iter().map(TrustAnchor::from) {
            let trust = self
                .trust_provider
                .get(&trust_anchor.r#type)
                .ok_or_else(|| {
                    MissingProviderError::TrustManager(trust_anchor.r#type.to_owned())
                })?;

            let did = self
                .did_repository
                .get_did(
                    &did_id,
                    &DidRelations {
                        organisation: Some(OrganisationRelations {}),
                        keys: None,
                    },
                )
                .await?
                .ok_or(ServiceError::EntityNotFound(EntityNotFoundError::Did(
                    did_id,
                )))?;

            let trust_entity = trust
                .lookup_entity_key(&trust_anchor, &(&did.did).into())
                .await
                .map_err(ServiceError::TrustManagementError)?;

            if let Some(trust_entity) = trust_entity {
                return trust_entity_from_partial_and_did_and_anchor(
                    trust_entity,
                    did,
                    None,
                    trust_anchor,
                );
            }
        }

        Err(ServiceError::BusinessLogic(
            BusinessLogicError::MissingTrustEntity(did_id),
        ))
    }

    pub async fn resolve_identifiers(
        &self,
        request: ResolveTrustEntitiesRequestDTO,
    ) -> Result<ResolveTrustEntitiesResponseDTO, ServiceError> {
        let (mut batches, mut batch_map) = self.prepare_lookup_batches(request).await?;

        let trust_anchor_list = self
            .trust_anchor_repository
            .list(ListTrustAnchorsQueryDTO {
                pagination: None,
                sorting: None,
                filtering: Some(
                    TrustAnchorFilterValue::Type(StringMatch::equals(SimpleTrustList.to_string()))
                        .condition(),
                ),
                include: None,
            })
            .await?;

        let mut result: HashMap<IdentifierId, Vec<ResolvedIdentifierTrustEntityResponseDTO>> =
            HashMap::new();
        for trust_anchor in trust_anchor_list.values.into_iter().map(TrustAnchor::from) {
            let trust = self
                .trust_provider
                .get(&trust_anchor.r#type)
                .ok_or_else(|| {
                    MissingProviderError::TrustManager(trust_anchor.r#type.to_owned())
                })?;

            let trust_entities = trust
                .lookup_entity_keys(&trust_anchor, &batches)
                .await
                .map_err(ServiceError::TrustManagementError)?;
            // no need to look up trust entities in the next anchor if they have already been found
            batches.retain(|batch| !trust_entities.contains_key(&batch.batch_id));

            for (batch_id, trust_entity) in trust_entities {
                let Some((identifier, certificate)) = batch_map.remove(&batch_id) else {
                    return Err(ServiceError::Other(format!(
                        "failed to retrieve identifier and certificate for batch {}",
                        &batch_id
                    )));
                };

                let identifier_id = identifier.id;
                let validated_trust_entity = match identifier.r#type {
                    IdentifierType::Key => {
                        // not supported at all -> fail hard
                        return Err(BusinessLogicError::IncompatibleIdentifierType {
                            reason: "Key identifier not supported".to_string(),
                        }
                        .into());
                    }
                    IdentifierType::Did => Ok(trust_entity_from_identifier_and_anchor(
                        trust_entity,
                        identifier,
                        trust_anchor.clone(),
                        None,
                    )),
                    IdentifierType::Certificate => {
                        if let Some(certificate) = &certificate {
                            self.validate_ca(&trust_entity, certificate)
                                .await
                                .map(|ca_cert| {
                                    trust_entity_from_identifier_and_anchor(
                                        trust_entity,
                                        identifier,
                                        trust_anchor.clone(),
                                        Some(ca_cert),
                                    )
                                })
                        } else {
                            return Err(ServiceError::Other(format!(
                                "failed to retrieve certificate for identifier {}",
                                identifier.id
                            )));
                        }
                    }
                };

                // validation is allowed to fail, silently ignore and drop it from the results
                let Ok(validated_trust_entity) = validated_trust_entity else {
                    tracing::info!(
                        "identifier `{identifier_id}`{} is not trusted{}",
                        certificate
                            .map(|cert| format!(" using certificate {}", cert.id))
                            .unwrap_or_default(),
                        validated_trust_entity
                            .err()
                            .map(|err| format!(": {err}"))
                            .unwrap_or_default()
                    );
                    continue;
                };

                let certificate_id = certificate.map(|c| c.id);
                let mut certificate_ids = certificate_id.map(|id| vec![id]).unwrap_or_default();

                // insert into result structure
                if let Some(previous_entry) = result.get_mut(&identifier_id) {
                    if let Some(previous_entity) = previous_entry
                        .iter_mut()
                        .find(|item| item.trust_entity.id == validated_trust_entity.id)
                    {
                        previous_entity.certificate_ids.append(&mut certificate_ids);
                    } else {
                        previous_entry.push(ResolvedIdentifierTrustEntityResponseDTO {
                            trust_entity: validated_trust_entity,
                            certificate_ids,
                        });
                    }
                } else {
                    result.insert(
                        identifier_id,
                        vec![ResolvedIdentifierTrustEntityResponseDTO {
                            trust_entity: validated_trust_entity,
                            certificate_ids,
                        }],
                    );
                }
            }
        }

        Ok(ResolveTrustEntitiesResponseDTO {
            identifier_to_trust_entity: result,
        })
    }

    async fn validate_ca(
        &self,
        trust_entity: &TrustEntityByEntityKey,
        certificate: &Certificate,
    ) -> Result<TrustEntityCertificateResponseDTO, ServiceError> {
        if trust_entity.r#type != TrustEntityType::CertificateAuthority {
            return Err(ServiceError::ValidationError(format!(
                "Cannot validate CA: trust_entity {} is not a CA",
                trust_entity.id
            )));
        }

        let Some(ca_chain) = &trust_entity.content else {
            return Err(ServiceError::ValidationError(format!(
                "Invalid trust_entity {}: content is missing",
                trust_entity.id
            )));
        };

        // validate whole chain
        let ParsedCertificate {
            attributes,
            public_key,
            subject_common_name,
            ..
        } = self
            .certificate_validator
            .validate_chain_against_ca_chain(
                &certificate.chain,
                ca_chain,
                CertificateValidationOptions::full_validation(None),
                CertSelection::LowestCaChain,
            )
            .await?;

        let public_key = hex::encode(public_key.public_key_as_raw());
        Ok(trust_entity_certificate_from_x509(
            // Only active CAs pass validation
            CertificateState::Active,
            public_key,
            subject_common_name,
            attributes,
        ))
    }

    async fn prepare_lookup_batches(
        &self,
        requests: ResolveTrustEntitiesRequestDTO,
    ) -> Result<
        (
            Vec<TrustEntityKeyBatch>,
            HashMap<String, (Identifier, Option<Certificate>)>,
        ),
        ServiceError,
    > {
        let mut batches = vec![];
        let mut batch_to_identifier_and_cert_map = HashMap::new();

        // This could be optimized to use batch lookup but that would require to implement the option
        // to include dids and certificates in the list lookup.
        for request in requests.identifiers {
            let identifier = self
                .identifier_repository
                .get(
                    request.id,
                    &IdentifierRelations {
                        certificates: Some(CertificateRelations::default()),
                        did: Some(DidRelations::default()),
                        ..Default::default()
                    },
                )
                .await?
                .ok_or(ServiceError::EntityNotFound(
                    EntityNotFoundError::Identifier(request.id),
                ))?;
            let (batch, certificate) = prepare_batch(&request, &identifier)?;
            batch_to_identifier_and_cert_map
                .insert(batch.batch_id.to_owned(), (identifier, certificate));
            batches.push(batch);
        }
        Ok((batches, batch_to_identifier_and_cert_map))
    }
}

fn prepare_batch(
    identifier_request: &ResolveTrustEntityRequestDTO,
    identifier: &Identifier,
) -> Result<(TrustEntityKeyBatch, Option<Certificate>), ServiceError> {
    match identifier.r#type {
        IdentifierType::Key => Err(ServiceError::BusinessLogic(
            BusinessLogicError::IncompatibleIdentifierType {
                reason: "Key identifier not supported".to_string(),
            },
        )),
        IdentifierType::Did => {
            if let Some(certificate_id) = identifier_request.certificate_id {
                return Err(IdentifierCertificateIdMismatch {
                    identifier_id: identifier_request.id.to_string(),
                    certificate_id: certificate_id.to_string(),
                }
                .into());
            }
            let did = identifier.did.as_ref().ok_or(MappingError(format!(
                "missing did on did identifier {}",
                identifier.id
            )))?;

            Ok((
                TrustEntityKeyBatch {
                    batch_id: identifier.id.to_string(),
                    trust_entity_keys: vec![TrustEntityKey::from(did.did.clone())],
                },
                None,
            ))
        }
        IdentifierType::Certificate => {
            let Some(certificate_id) = identifier_request.certificate_id else {
                return Err(BusinessLogicError::CertificateIdNotSpecified)?;
            };
            let certificates = identifier
                .certificates
                .as_ref()
                .ok_or(MappingError(format!(
                    "missing certificates on certificate identifier {}",
                    identifier.id
                )))?;
            let certificate = certificates
                .iter()
                .find(|cert| cert.id == certificate_id)
                .ok_or(BusinessLogicError::IdentifierCertificateIdMismatch {
                    identifier_id: identifier_request.id.to_string(),
                    certificate_id: certificate_id.to_string(),
                })?;
            let trust_entity_keys = pem_chain_to_authority_key_identifiers(&certificate.chain)
                .map_err(|err| {
                    ServiceError::Other(format!(
                        "failed to extract authority key identifiers for certificate {}: {err}",
                        certificate.id
                    ))
                })?
                .into_iter()
                .map(TrustEntityKey::from)
                .collect();
            let batch = TrustEntityKeyBatch {
                batch_id: certificate.id.to_string(),
                trust_entity_keys,
            };

            Ok((batch, Some(certificate.clone())))
        }
    }
}
