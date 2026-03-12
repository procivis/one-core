use std::collections::HashMap;

use shared_types::{DidId, DidValue, IdentifierId, TrustAnchorId, TrustEntityId, TrustEntityKey};
use uuid::Uuid;

use super::TrustEntityService;
use super::dto::{
    CreateTrustEntityFromDidPublisherRequestDTO, CreateTrustEntityParamsDTO,
    CreateTrustEntityRequestDTO, CreateTrustEntityTypeDTO, GetTrustEntitiesResponseDTO,
    GetTrustEntityResponseDTO, ListTrustEntitiesQueryDTO, ResolveTrustEntitiesRequestDTO,
    ResolveTrustEntitiesResponseDTO, ResolveTrustEntityRequestDTO,
    ResolvedIdentifierTrustEntityResponseDTO, TrustEntityCertificateResponseDTO,
    TrustEntityContent, UpdateTrustEntityActionFromDidRequestDTO,
    UpdateTrustEntityFromDidRequestDTO,
};
use super::error::TrustEntityServiceError;
use super::mapper::{
    get_detail_trust_entity_response, trust_entity_certificate_from_x509,
    trust_entity_from_did_request, trust_entity_from_identifier_and_anchor,
    trust_entity_from_partial_and_did_and_anchor, trust_entity_from_request,
    update_request_from_dto,
};
use crate::config::core_config::TrustManagementType::SimpleTrustList;
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::mapper::x509::pem_chain_to_authority_key_identifiers;
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
use crate::proto::bearer_token::validate_bearer_token;
use crate::proto::certificate_validator::{
    CertSelection, CertificateValidationOptions, CrlMode, ParsedCertificate,
};
use crate::proto::identifier_creator::IdentifierRole;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::trust_management::model::TrustEntityByEntityKey;
use crate::provider::trust_management::{TrustEntityKeyBatch, TrustOperation};
use crate::repository::error::DataLayerError;
use crate::service::error::MissingProviderError;
use crate::service::trust_anchor::dto::{ListTrustAnchorsQueryDTO, TrustAnchorFilterValue};

impl TrustEntityService {
    pub async fn create_trust_entity(
        &self,
        request: CreateTrustEntityRequestDTO,
    ) -> Result<TrustEntityId, TrustEntityServiceError> {
        let trust_anchor = self
            .trust_anchor_repository
            .get(request.trust_anchor_id)
            .await
            .error_while("getting trust anchor")?
            .ok_or(TrustEntityServiceError::MissingTrustAnchor(
                request.trust_anchor_id,
            ))?;

        if !trust_anchor.is_publisher {
            return Err(TrustEntityServiceError::TrustAnchorMustBePublish);
        }

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &Default::default())
            .await
            .error_while("getting organisation")?
            .ok_or(TrustEntityServiceError::MissingOrganisation(
                request.organisation_id,
            ))?;

        if organisation.deactivated_at.is_some() {
            return Err(TrustEntityServiceError::OrganisationIsDeactivated(
                request.organisation_id,
            ));
        }

        let (entity_type, entity_params) = request.try_into()?;

        let trust_anchor_id = trust_anchor.id;
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

        let success_log = format!(
            "Created trust entity `{}` ({}) using trust anchor {trust_anchor_id}",
            trust_entity.name, trust_entity.id
        );
        let id = self
            .trust_entity_repository
            .create(trust_entity)
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => TrustEntityServiceError::AlreadyExists,
                err => err.error_while("creating trust entity").into(),
            })?;
        tracing::info!(message = success_log);
        Ok(id)
    }

    async fn trust_entity_from_certificate_params(
        &self,
        content: TrustEntityContent,
        params: CreateTrustEntityParamsDTO,
        trust_anchor: TrustAnchor,
        organisation: Organisation,
    ) -> Result<TrustEntity, TrustEntityServiceError> {
        let certificate = self
            .certificate_validator
            .parse_pem_chain(
                &content,
                CertificateValidationOptions::full_validation(None),
            )
            .await
            .error_while("parsing PEM chain")?;

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
    ) -> Result<TrustEntity, TrustEntityServiceError> {
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
            .await
            .error_while("getting identifier")?
            .ok_or(TrustEntityServiceError::MissingIdentifier(identifier_id))?;

        let Some(did) = identifier.did else {
            return Err(TrustEntityServiceError::IncompatibleIdentifierType {
                reason: "trust entity only supports did identifiers".to_string(),
            });
        };

        if did.did_type == DidType::Remote {
            return Err(TrustEntityServiceError::IncompatibleDidType {
                reason: "Only local DIDs allowed".to_string(),
            });
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
    ) -> Result<TrustEntity, TrustEntityServiceError> {
        let did = self
            .did_repository
            .get_did(
                &did_id,
                &DidRelations {
                    organisation: Some(OrganisationRelations {}),
                    keys: None,
                },
            )
            .await
            .error_while("getting did")?
            .ok_or(TrustEntityServiceError::MissingDid(did_id))?;

        if did.did_type == DidType::Remote {
            return Err(TrustEntityServiceError::IncompatibleDidType {
                reason: "Only local DIDs allowed".to_string(),
            });
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
    ) -> Result<TrustEntityId, TrustEntityServiceError> {
        let did_value = request.did.clone();

        let trust_anchor = self.get_trust_anchor(request.trust_anchor_id, true).await?;

        let trust_params: crate::provider::trust_management::simple_list::Params = self
            .config
            .trust_management
            .get(&trust_anchor.r#type)
            .error_while("getting trust anchor params")?;
        self.validate_bearer_token(
            &did_value,
            bearer_token,
            trust_params.proof_of_possession_leeway,
        )
        .await?;

        if !trust_anchor.is_publisher {
            return Err(TrustEntityServiceError::TrustAnchorMustBePublish);
        }

        let trust = self
            .trust_provider
            .get(&trust_anchor.r#type)
            .ok_or_else(|| MissingProviderError::TrustManager(trust_anchor.r#type.clone()))
            .error_while("getting trust manager")?;

        if !trust
            .get_capabilities()
            .operations
            .contains(&TrustOperation::Publish)
        {
            return Err(TrustEntityServiceError::TrustAnchorIsDisabled);
        }

        if self
            .trust_entity_repository
            .get_by_entity_key(&(&did_value).into())
            .await
            .error_while("getting trust entity")?
            .is_some()
        {
            return Err(TrustEntityServiceError::AlreadyExists);
        }

        let did_role = match request.role {
            TrustEntityRole::Issuer => IdentifierRole::Issuer,
            TrustEntityRole::Verifier => IdentifierRole::Verifier,
            TrustEntityRole::Both => IdentifierRole::Issuer,
        };

        // See: ONE-6304, we expect the remote DID to be available at a later stage
        let _unused = self
            .identifier_creator
            .get_or_create_remote_identifier(
                &None,
                &IdentifierDetails::Did(did_value.to_owned()),
                did_role,
            )
            .await
            .error_while(format!("creating remote {:?} identifier", request.role))?;

        let entity = trust_entity_from_did_request(request, trust_anchor.clone(), did_value);

        trust.publish_entity(&trust_anchor, &entity).await;

        self.trust_entity_repository
            .create(entity)
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => TrustEntityServiceError::AlreadyExists,
                err => err.error_while("creating trust entity").into(),
            })
    }

    pub async fn get_trust_entity(
        &self,
        id: TrustEntityId,
    ) -> Result<GetTrustEntityResponseDTO, TrustEntityServiceError> {
        let trust_entity = self
            .trust_entity_repository
            .get(
                id,
                &TrustEntityRelations {
                    trust_anchor: Some(TrustAnchorRelations::default()),
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await
            .error_while("getting trust entity")?
            .ok_or(TrustEntityServiceError::NotFound(id))?;

        let (mut identifier, content) = match &trust_entity.r#type {
            TrustEntityType::Did => {
                let did_value = DidValue::from_did_url(&trust_entity.entity_key).map_err(|_| {
                    TrustEntityServiceError::MappingError(
                        "invalid trust_entity.entity_key for type did".to_string(),
                    )
                })?;
                let organisation_id = trust_entity.organisation.as_ref().map(|o| o.id);

                let did = self
                    .did_repository
                    .get_did_by_value(&did_value, Some(organisation_id), &DidRelations::default())
                    .await
                    .error_while("getting did")?
                    .ok_or(TrustEntityServiceError::MissingDidValue(did_value))?;

                let mut identifier = self
                    .identifier_repository
                    .get_from_did_id(did.id, &IdentifierRelations::default())
                    .await
                    .error_while("getting identifier")?
                    .ok_or(TrustEntityServiceError::MissingIdentifierByDidId(did.id))?;

                identifier.did = Some(did);
                (Some(identifier), None)
            }
            TrustEntityType::CertificateAuthority => {
                let pem_chain =
                    trust_entity
                        .content
                        .as_ref()
                        .ok_or(TrustEntityServiceError::MappingError(
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
                            leaf_validations: Default::default(),
                        },
                    )
                    .await
                {
                    Ok(parsed) => (CertificateState::Active, parsed),
                    Err(error) if error.error_code() == ErrorCode::BR_0359 => (
                        CertificateState::NotYetActive,
                        unchecked_certificate()
                            .await
                            .error_while("parsing certificate")?,
                    ),
                    Err(error) if error.error_code() == ErrorCode::BR_0213 => (
                        CertificateState::Expired,
                        unchecked_certificate()
                            .await
                            .error_while("parsing certificate")?,
                    ),
                    Err(error) if error.error_code() == ErrorCode::BR_0212 => (
                        CertificateState::Revoked,
                        unchecked_certificate()
                            .await
                            .error_while("parsing certificate")?,
                    ),
                    Err(err) => {
                        return Err(err.error_while("parsing PEM chain").into());
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
    ) -> Result<GetTrustEntityResponseDTO, TrustEntityServiceError> {
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
            .await
            .error_while("getting did")?
            .ok_or(TrustEntityServiceError::MissingDidValue(did_value.clone()))?;
        let entity_key: TrustEntityKey = did_value.clone().into();

        let result = self
            .trust_entity_repository
            .get_by_entity_key(&entity_key)
            .await
            .error_while("getting trust entity")?
            .ok_or(TrustEntityServiceError::NotFoundByEntityKey(entity_key))?;

        let leeway = self.get_proof_of_possession_leeway(&result)?;
        self.validate_bearer_token(&did_value, bearer_token, leeway)
            .await?;

        get_detail_trust_entity_response(result, Some(did), None, None)
    }

    pub async fn list_trust_entities(
        &self,
        filters: ListTrustEntitiesQueryDTO,
    ) -> Result<GetTrustEntitiesResponseDTO, TrustEntityServiceError> {
        Ok(self
            .trust_entity_repository
            .list(filters)
            .await
            .error_while("getting trust entities")?)
    }

    async fn update_trust_entity(
        &self,
        entity: TrustEntity,
        request: UpdateTrustEntityFromDidRequestDTO,
    ) -> Result<(), TrustEntityServiceError> {
        if let Some(content) = &request.content {
            match entity.r#type {
                TrustEntityType::Did => return Err(TrustEntityServiceError::InvalidType),
                TrustEntityType::CertificateAuthority => {
                    let cert = self
                        .certificate_validator
                        .parse_pem_chain(
                            content,
                            CertificateValidationOptions::full_validation(None),
                        )
                        .await
                        .error_while("parsing PEM chain")?;
                    if entity.entity_key != TrustEntityKey::try_from(&cert)? {
                        return Err(TrustEntityServiceError::SubjectKeyIdentifierDoesNotMatch);
                    }
                }
            }
        }

        let request = update_request_from_dto(entity.state, request)?;

        self.trust_entity_repository
            .update(entity.id, request)
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => TrustEntityServiceError::AlreadyExists,
                err => err.error_while("updating trust entity").into(),
            })?;

        Ok(())
    }

    // PUBLISHER or NON-PUBLISHER
    pub async fn update_trust_entity_by_trust_entity(
        &self,
        id: TrustEntityId,
        update_request: UpdateTrustEntityFromDidRequestDTO,
    ) -> Result<(), TrustEntityServiceError> {
        let entity = self
            .trust_entity_repository
            .get(
                id,
                &TrustEntityRelations {
                    ..Default::default()
                },
            )
            .await
            .error_while("getting trust entity")?
            .ok_or(TrustEntityServiceError::NotFound(id))?;

        self.update_trust_entity(entity, update_request).await?;

        Ok(())
    }

    // NON-PUBLISHER
    pub async fn update_trust_entity_by_did(
        &self,
        did_value: DidValue,
        request: UpdateTrustEntityFromDidRequestDTO,
        bearer_token: &str,
    ) -> Result<(), TrustEntityServiceError> {
        // only allowed to withdraw/activate
        if matches!(
            request.action,
            Some(
                UpdateTrustEntityActionFromDidRequestDTO::Remove
                    | UpdateTrustEntityActionFromDidRequestDTO::AdminActivate,
            )
        ) {
            return Err(TrustEntityServiceError::InvalidUpdateRequest);
        }

        let Some(did) = self
            .did_repository
            .get_did_by_value(&did_value, Some(None), &DidRelations::default())
            .await
            .error_while("getting did")?
        else {
            return Err(TrustEntityServiceError::MissingDidValue(did_value));
        };

        let Some(entity) = self
            .trust_entity_repository
            .get_by_entity_key(&did.did.into())
            .await
            .error_while("getting trust entity")?
        else {
            return Err(TrustEntityServiceError::Duplicates);
        };

        let leeway = self.get_proof_of_possession_leeway(&entity)?;
        self.validate_bearer_token(&did_value, bearer_token, leeway)
            .await?;

        self.update_trust_entity(entity.clone(), request).await?;

        Ok(())
    }

    async fn validate_bearer_token(
        &self,
        did_value: &DidValue,
        bearer_token: &str,
        leeway: u64,
    ) -> Result<(), TrustEntityServiceError> {
        let jwt = validate_bearer_token(
            bearer_token,
            self.did_method_provider.clone(),
            self.key_algorithm_provider.clone(),
            self.certificate_validator.clone(),
            leeway,
        )
        .await
        .error_while("validating bearer token")?;

        let token_issuer = jwt
            .payload
            .issuer
            .ok_or(TrustEntityServiceError::Forbidden)?;

        if token_issuer != did_value.as_str() {
            return Err(TrustEntityServiceError::Forbidden);
        }

        Ok(())
    }

    pub(super) async fn get_trust_anchor(
        &self,
        trust_anchor_id: Option<TrustAnchorId>,
        is_publisher: bool,
    ) -> Result<TrustAnchor, TrustEntityServiceError> {
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
                    .await
                    .error_while("getting trust anchors")?;
                if anchors.values.len() > 1 {
                    return Err(TrustEntityServiceError::MultipleMatchingTrustAnchors);
                }
                let trust_anchor =
                    anchors
                        .values
                        .first()
                        .ok_or(TrustEntityServiceError::MissingTrustAnchor(
                            Uuid::default().into(),
                        ))?;
                Ok(trust_anchor.clone().into())
            }
            Some(trust_anchor_id) => Ok(self
                .trust_anchor_repository
                .get(trust_anchor_id)
                .await
                .error_while("getting trust anchor")?
                .ok_or(TrustEntityServiceError::MissingTrustAnchor(trust_anchor_id))?),
        }
    }

    pub async fn lookup_did(
        &self,
        did_id: DidId,
    ) -> Result<GetTrustEntityResponseDTO, TrustEntityServiceError> {
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
            .await
            .error_while("getting trust anchors")?;

        for trust_anchor in trust_anchor_list.values.into_iter().map(TrustAnchor::from) {
            let trust = self
                .trust_provider
                .get(&trust_anchor.r#type)
                .ok_or_else(|| MissingProviderError::TrustManager(trust_anchor.r#type.to_owned()))
                .error_while("getting trust manager")?;

            let did = self
                .did_repository
                .get_did(
                    &did_id,
                    &DidRelations {
                        organisation: Some(OrganisationRelations {}),
                        keys: None,
                    },
                )
                .await
                .error_while("getting did")?
                .ok_or(TrustEntityServiceError::MissingDid(did_id))?;

            let trust_entity = trust
                .lookup_entity_key(&trust_anchor, &(&did.did).into())
                .await?;

            if let Some(trust_entity) = trust_entity {
                return Ok(trust_entity_from_partial_and_did_and_anchor(
                    trust_entity,
                    did,
                    None,
                    trust_anchor,
                ));
            }
        }

        Err(TrustEntityServiceError::NotFoundForDid(did_id))
    }

    pub async fn resolve_identifiers(
        &self,
        request: ResolveTrustEntitiesRequestDTO,
    ) -> Result<ResolveTrustEntitiesResponseDTO, TrustEntityServiceError> {
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
            .await
            .error_while("getting trust anchors")?;

        let mut result: HashMap<IdentifierId, Vec<ResolvedIdentifierTrustEntityResponseDTO>> =
            HashMap::new();
        for trust_anchor in trust_anchor_list.values.into_iter().map(TrustAnchor::from) {
            let trust = self
                .trust_provider
                .get(&trust_anchor.r#type)
                .ok_or_else(|| MissingProviderError::TrustManager(trust_anchor.r#type.to_owned()))
                .error_while("getting trust manager")?;

            let trust_entities = trust.lookup_entity_keys(&trust_anchor, &batches).await?;
            // no need to look up trust entities in the next anchor if they have already been found
            batches.retain(|batch| !trust_entities.contains_key(&batch.batch_id));

            for (batch_id, trust_entity) in trust_entities {
                let Some((identifier, certificate)) = batch_map.remove(&batch_id) else {
                    return Err(TrustEntityServiceError::MappingError(format!(
                        "failed to retrieve identifier and certificate for batch {}",
                        &batch_id
                    )));
                };

                let identifier_id = identifier.id;
                if let Some(resolved) = self
                    .resolve_batch(trust_entity, &trust_anchor, identifier, certificate)
                    .await?
                {
                    // insert into result structure
                    result
                        .entry(identifier_id)
                        .and_modify({
                            let resolved = resolved.clone();
                            |previous_entry| {
                                if let Some(previous_entity) = previous_entry
                                    .iter_mut()
                                    .find(|item| item.trust_entity.id == resolved.trust_entity.id)
                                {
                                    previous_entity
                                        .certificate_ids
                                        .extend(resolved.certificate_ids);
                                } else {
                                    previous_entry.push(resolved);
                                }
                            }
                        })
                        .or_insert(vec![resolved]);
                };
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
    ) -> Result<TrustEntityCertificateResponseDTO, TrustEntityServiceError> {
        if trust_entity.r#type != TrustEntityType::CertificateAuthority {
            return Err(TrustEntityServiceError::MappingError(format!(
                "Cannot validate CA: trust_entity {} is not a CA",
                trust_entity.id
            )));
        }

        let Some(ca_chain) = &trust_entity.content else {
            return Err(TrustEntityServiceError::MappingError(format!(
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
            .await
            .error_while("validating certificate")?;

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
        TrustEntityServiceError,
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
                .await
                .error_while("getting identifier")?
                .ok_or(TrustEntityServiceError::MissingIdentifier(request.id))?;
            let (batch, certificate) = prepare_batch(&request, &identifier)?;
            batch_to_identifier_and_cert_map
                .insert(batch.batch_id.to_owned(), (identifier, certificate));
            batches.push(batch);
        }
        Ok((batches, batch_to_identifier_and_cert_map))
    }

    async fn resolve_batch(
        &self,
        trust_entity: TrustEntityByEntityKey,
        trust_anchor: &TrustAnchor,
        identifier: Identifier,
        certificate: Option<Certificate>,
    ) -> Result<Option<ResolvedIdentifierTrustEntityResponseDTO>, TrustEntityServiceError> {
        let identifier_id = identifier.id;
        let validated_trust_entity = match identifier.r#type {
            IdentifierType::Key => {
                // not supported at all -> fail hard
                return Err(TrustEntityServiceError::IncompatibleIdentifierType {
                    reason: "Key identifier not supported".to_string(),
                });
            }
            IdentifierType::Did => Ok(trust_entity_from_identifier_and_anchor(
                trust_entity,
                identifier,
                trust_anchor.clone(),
                None,
            )),
            IdentifierType::Certificate | IdentifierType::CertificateAuthority => {
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
                    return Err(TrustEntityServiceError::MappingError(format!(
                        "failed to retrieve certificate for identifier {identifier_id}",
                    )));
                }
            }
        };

        let Ok(validated_trust_entity) = validated_trust_entity else {
            // validation is allowed to fail, ignore and drop it from the results
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
            return Ok(None);
        };

        let mut certificate_ids = vec![];
        if let Some(certificate) = certificate {
            certificate_ids.push(certificate.id);
        };

        Ok(Some(ResolvedIdentifierTrustEntityResponseDTO {
            trust_entity: validated_trust_entity,
            certificate_ids,
        }))
    }

    fn get_proof_of_possession_leeway(
        &self,
        entity: &TrustEntity,
    ) -> Result<u64, TrustEntityServiceError> {
        let anchor = entity
            .trust_anchor
            .as_ref()
            .ok_or(TrustEntityServiceError::MappingError(
                "TrustEntity with no TrustAnchor".to_owned(),
            ))?;
        let trust_params: crate::provider::trust_management::simple_list::Params = self
            .config
            .trust_management
            .get(&anchor.r#type)
            .error_while("getting trust anchor params")?;
        Ok(trust_params.proof_of_possession_leeway)
    }
}

fn prepare_batch(
    identifier_request: &ResolveTrustEntityRequestDTO,
    identifier: &Identifier,
) -> Result<(TrustEntityKeyBatch, Option<Certificate>), TrustEntityServiceError> {
    match identifier.r#type {
        IdentifierType::Key => Err(TrustEntityServiceError::IncompatibleIdentifierType {
            reason: "Key identifier not supported".to_string(),
        }),
        IdentifierType::Did => {
            if let Some(certificate_id) = identifier_request.certificate_id {
                return Err(TrustEntityServiceError::IdentifierCertificateIdMismatch {
                    identifier_id: identifier_request.id.to_string(),
                    certificate_id: certificate_id.to_string(),
                });
            }
            let did = identifier
                .did
                .as_ref()
                .ok_or(TrustEntityServiceError::MappingError(format!(
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
        IdentifierType::Certificate | IdentifierType::CertificateAuthority => {
            let Some(certificate_id) = identifier_request.certificate_id else {
                return Err(TrustEntityServiceError::CertificateIdNotSpecified)?;
            };
            let certificates =
                identifier
                    .certificates
                    .as_ref()
                    .ok_or(TrustEntityServiceError::MappingError(format!(
                        "missing certificates on {} identifier {}",
                        identifier.r#type, identifier.id
                    )))?;
            let certificate = certificates
                .iter()
                .find(|cert| cert.id == certificate_id)
                .ok_or(TrustEntityServiceError::IdentifierCertificateIdMismatch {
                    identifier_id: identifier_request.id.to_string(),
                    certificate_id: certificate_id.to_string(),
                })?;
            let trust_entity_keys = pem_chain_to_authority_key_identifiers(&certificate.chain)
                .error_while("parsing PEM chain")?
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
