use async_trait::async_trait;
use one_core::model::certificate::{
    Certificate, CertificateListQuery, CertificateRelations, GetCertificateList,
    UpdateCertificateRequest,
};
use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::error::DataLayerError;
use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait, QueryOrder, Set, Unchanged};
use shared_types::CertificateId;
use time::OffsetDateTime;

use super::CertificateProvider;
use super::mapper::create_list_response;
use crate::entity::{certificate, identifier};
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

impl CertificateProvider {
    async fn resolve_relations(
        &self,
        model: certificate::Model,
        relations: &CertificateRelations,
    ) -> Result<Certificate, DataLayerError> {
        let mut result: Certificate = model.clone().into();

        if let Some(key_relations) = &relations.key {
            if let Some(key_id) = &model.key_id {
                result.key = Some(
                    self.key_repository
                        .get_key(key_id, key_relations)
                        .await?
                        .ok_or(DataLayerError::MissingRequiredRelation {
                            relation: "certificate-key",
                            id: key_id.to_string(),
                        })?,
                );
            }
        }

        if let Some(organisation_relations) = &relations.organisation {
            let identifier = identifier::Entity::find_by_id(model.identifier_id)
                .one(&self.db)
                .await
                .map_err(to_data_layer_error)?
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "certificate-identifier",
                    id: model.identifier_id.to_string(),
                })?;

            if let Some(organisation_id) = identifier.organisation_id {
                result.organisation = Some(
                    self.organisation_repository
                        .get_organisation(&organisation_id, organisation_relations)
                        .await?
                        .ok_or(DataLayerError::MissingRequiredRelation {
                            relation: "certificate-organisation",
                            id: organisation_id.to_string(),
                        })?,
                );
            }
        }

        Ok(result)
    }
}

#[async_trait]
impl CertificateRepository for CertificateProvider {
    async fn create(&self, request: Certificate) -> Result<CertificateId, DataLayerError> {
        let identifier = certificate::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(identifier.id)
    }

    async fn get(
        &self,
        id: CertificateId,
        relations: &CertificateRelations,
    ) -> Result<Option<Certificate>, DataLayerError> {
        let certificate = certificate::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        match certificate {
            None => Ok(None),
            Some(certificate) => Ok(Some(self.resolve_relations(certificate, relations).await?)),
        }
    }

    async fn list(
        &self,
        query_params: CertificateListQuery,
    ) -> Result<GetCertificateList, DataLayerError> {
        let query = certificate::Entity::find()
            .with_list_query(&query_params)
            .order_by_desc(certificate::Column::CreatedDate)
            .order_by_desc(certificate::Column::Id);

        let limit = query_params
            .pagination
            .map(|pagination| pagination.page_size as u64);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let certificates: Vec<certificate::Model> = query
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(create_list_response(certificates, limit, items_count))
    }

    async fn update(
        &self,
        id: &CertificateId,
        request: UpdateCertificateRequest,
    ) -> Result<(), DataLayerError> {
        let update_model = certificate::ActiveModel {
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
}
