use async_trait::async_trait;
use one_core::model::identifier::{
    GetIdentifierList, Identifier, IdentifierListQuery, IdentifierRelations,
    UpdateIdentifierRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::identifier_repository::IdentifierRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Select, Set,
    Unchanged,
};
use shared_types::{CertificateId, DidId, IdentifierId};
use time::OffsetDateTime;

use super::IdentifierProvider;
use crate::common::list_query_with_base_model;
use crate::entity::{certificate, identifier};
use crate::list_query_generic::{SelectWithFilterJoin, SelectWithListQuery};
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

impl IdentifierProvider {
    async fn resolve_relations(
        &self,
        model: identifier::Model,
        relations: &IdentifierRelations,
    ) -> Result<Identifier, DataLayerError> {
        let mut result: Identifier = model.clone().into();

        if let Some(organisation_relations) = &relations.organisation
            && let Some(organisation_id) = &model.organisation_id
        {
            result.organisation = Some(
                self.organisation_repository
                    .get_organisation(organisation_id, organisation_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "identifier-organisation",
                        id: organisation_id.to_string(),
                    })?,
            );
        }

        if model.r#type == identifier::IdentifierType::Did
            && let Some(did_relations) = &relations.did
            && let Some(did_id) = &model.did_id
        {
            result.did = Some(
                self.did_repository
                    .get_did(did_id, did_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "identifier-did",
                        id: did_id.to_string(),
                    })?,
            );
        }

        if model.r#type == identifier::IdentifierType::Key
            && let Some(key_relations) = &relations.key
            && let Some(key_id) = &model.key_id
        {
            result.key = Some(
                self.key_repository
                    .get_key(key_id, key_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "identifier-key",
                        id: key_id.to_string(),
                    })?,
            );
        }

        if (model.r#type == identifier::IdentifierType::Certificate
            || model.r#type == identifier::IdentifierType::CertificateAuthority)
            && let Some(certificate_relations) = &relations.certificates
        {
            let certificate_ids: Vec<CertificateId> = certificate::Entity::find()
                .select_only()
                .column(certificate::Column::Id)
                .filter(certificate::Column::IdentifierId.eq(model.id))
                .order_by_desc(certificate::Column::ExpiryDate)
                .order_by_asc(certificate::Column::Name)
                .into_tuple()
                .all(&self.db)
                .await
                .map_err(to_data_layer_error)?;

            let mut certs = vec![];
            for certificate_id in certificate_ids {
                certs.push(
                    self.certificate_repository
                        .get(certificate_id, certificate_relations)
                        .await?
                        .ok_or(DataLayerError::MissingRequiredRelation {
                            relation: "identifier-certificate",
                            id: certificate_id.to_string(),
                        })?,
                );
            }
            result.certificates = Some(certs);
        }

        Ok(result)
    }
}

#[async_trait]
impl IdentifierRepository for IdentifierProvider {
    async fn create(&self, request: Identifier) -> Result<IdentifierId, DataLayerError> {
        let identifier = identifier::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(identifier.id)
    }

    async fn get(
        &self,
        id: IdentifierId,
        relations: &IdentifierRelations,
    ) -> Result<Option<Identifier>, DataLayerError> {
        let identifier = identifier::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        match identifier {
            None => Ok(None),
            Some(identifier) => Ok(Some(self.resolve_relations(identifier, relations).await?)),
        }
    }

    async fn get_from_did_id(
        &self,
        did_id: DidId,
        relations: &IdentifierRelations,
    ) -> Result<Option<Identifier>, DataLayerError> {
        let identifier = identifier::Entity::find()
            .filter(identifier::Column::DidId.eq(did_id))
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        match identifier {
            None => Ok(None),
            Some(identifier) => Ok(Some(self.resolve_relations(identifier, relations).await?)),
        }
    }

    async fn update(
        &self,
        id: &IdentifierId,
        request: UpdateIdentifierRequest,
    ) -> Result<(), DataLayerError> {
        let update_model = identifier::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(OffsetDateTime::now_utc()),
            name: request.name.map(Set).unwrap_or_default(),
            state: request
                .state
                .map(|state| Set(state.into()))
                .unwrap_or_default(),
            ..Default::default()
        };

        update_model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn delete(&self, id: &IdentifierId) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

        let identifier = identifier::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(now),
            deleted_at: Set(Some(now)),
            ..Default::default()
        };

        identifier::Entity::update(identifier)
            .filter(identifier::Column::DeletedAt.is_null())
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn get_identifier_list(
        &self,
        query_params: IdentifierListQuery,
    ) -> Result<GetIdentifierList, DataLayerError> {
        let query = get_identifier_list_query(&query_params);

        list_query_with_base_model(query, query_params, &self.db).await
    }
}

fn get_identifier_list_query(query_params: &IdentifierListQuery) -> Select<identifier::Entity> {
    identifier::Entity::find()
        .select_only()
        .columns([
            identifier::Column::Id,
            identifier::Column::CreatedDate,
            identifier::Column::LastModified,
            identifier::Column::Name,
            identifier::Column::Type,
            identifier::Column::IsRemote,
            identifier::Column::State,
            identifier::Column::OrganisationId,
            identifier::Column::DidId,
            identifier::Column::KeyId,
            identifier::Column::DeletedAt,
        ])
        .filter(identifier::Column::DeletedAt.is_null())
        .with_filter_join(query_params)
        .with_list_query(query_params)
        .group_by(identifier::Column::Id)
        .group_by(identifier::Column::CreatedDate)
        .group_by(identifier::Column::LastModified)
        .group_by(identifier::Column::Name)
        .group_by(identifier::Column::Type)
        .group_by(identifier::Column::IsRemote)
        .group_by(identifier::Column::State)
        .group_by(identifier::Column::OrganisationId)
        .group_by(identifier::Column::DidId)
        .group_by(identifier::Column::KeyId)
        .group_by(identifier::Column::DeletedAt)
        .order_by_desc(identifier::Column::CreatedDate)
        .order_by_desc(identifier::Column::Id)
}
