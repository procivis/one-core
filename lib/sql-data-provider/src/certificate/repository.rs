use std::str::FromStr;

use async_trait::async_trait;
use migration::supported_db_type::WithSupportedDbType;
use one_core::model::certificate::{
    Certificate, CertificateListQuery, CertificateRole, GetCertificateList,
    UpdateCertificateRequest,
};
use one_core::model::relation::Related;
use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::error::{DataLayerError, EntityKind};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set, Unchanged,
};
use shared_types::CertificateId;

use super::CertificateProvider;
use crate::common::list_query_with_custom_model;
use crate::entity::certificate;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

impl CertificateProvider {
    fn model_to_certificate(
        &self,
        model: certificate::Model,
    ) -> Result<Certificate, DataLayerError> {
        let roles = if let Some(value) = model.roles {
            value
                .split(",")
                .map(CertificateRole::from_str)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| DataLayerError::MappingError)?
        } else {
            vec![]
        };

        Ok(Certificate {
            id: model.id,
            identifier_id: model.identifier_id,
            created_date: model.created_date,
            last_modified: model.last_modified,
            expiry_date: model.expiry_date,
            name: model.name,
            chain: model.chain,
            fingerprint: model.fingerprint,
            state: model.state.into(),
            roles,
            key: model
                .key_id
                .map(|key_id| Related::new(key_id, self.key_repository.clone())),
            organisation: Related::new(model.organisation_id, self.organisation_repository.clone()),
            deleted_at: model.deleted_at,
        })
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

    async fn get(&self, id: CertificateId) -> Result<Certificate, DataLayerError> {
        let certificate = certificate::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::Certificate,
                id: id.into(),
            })?;

        self.model_to_certificate(certificate)
    }

    async fn list(
        &self,
        query_params: CertificateListQuery,
    ) -> Result<GetCertificateList, DataLayerError> {
        let query = certificate::Entity::find()
            .with_list_query(&query_params, self.db.supported_db_type())
            .order_by_desc(certificate::Column::CreatedDate)
            .order_by_desc(certificate::Column::Id);

        list_query_with_custom_model(query, query_params, &self.db, |model| {
            self.model_to_certificate(model)
        })
        .await
    }

    async fn update(
        &self,
        id: &CertificateId,
        request: UpdateCertificateRequest,
    ) -> Result<(), DataLayerError> {
        let update_model = certificate::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(one_core::clock::now_utc()),
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

    async fn delete(&self, certificate: &Certificate) -> Result<(), DataLayerError> {
        let now = one_core::clock::now_utc();

        let update_model = certificate::ActiveModel {
            id: Unchanged(certificate.id),
            deleted_at: Set(Some(now)),
            ..Default::default()
        };

        certificate::Entity::update(update_model)
            .validate()
            .map_err(to_update_data_layer_error)?
            .filter(certificate::Column::DeletedAt.is_null())
            .exec(&self.db)
            .await
            .map(|_| ())
            .map_err(to_update_data_layer_error)
    }
}
