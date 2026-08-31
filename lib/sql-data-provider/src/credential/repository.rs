use std::collections::HashSet;

use autometrics::autometrics;
use futures::FutureExt;
use one_core::model::claim::Claim;
use one_core::model::credential::{
    Credential, CredentialListIncludeEntityTypeEnum, CredentialListQuery, GetCredentialList,
    UpdateCredentialRequest,
};
use one_core::proto::transaction_manager::IsolationLevel;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::error::{DataLayerError, EntityKind};
use sea_orm::ActiveValue::NotSet;
use sea_orm::sea_query::{Expr, IntoCondition};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, JoinType, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, RelationTrait, Select, Set, SqlErr, Unchanged,
};
use shared_types::{CredentialId, InteractionId};

use super::CredentialProvider;
use super::entity_model::CredentialListEntityModel;
use super::mapper::{
    credentials_to_repository, from_clearable, model_to_credential, request_to_active_model,
};
use crate::common::calculate_pages_count;
use crate::entity::{claim, claim_schema, credential, credential_schema, identifier};
use crate::list_query_generic::{SelectWithFilterJoin, SelectWithListQuery};
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

impl CredentialProvider {
    fn credential_model_to_repository_model(&self, credential: credential::Model) -> Credential {
        model_to_credential(
            credential,
            &self.cloned(),
            &self.claim_repository,
            &self.credential_schema_repository,
            &self.key_repository,
            &self.identifier_repository,
            &self.certificate_repository,
            &self.interaction_repository,
            &self.db,
        )
    }

    fn credentials_to_repository(&self, credentials: Vec<credential::Model>) -> Vec<Credential> {
        credentials
            .into_iter()
            .map(|model| self.credential_model_to_repository_model(model))
            .collect()
    }

    async fn update_claims(
        &self,
        credential_id: CredentialId,
        claims: Option<Vec<Claim>>,
    ) -> Result<(), DataLayerError> {
        if let Some(claims) = claims {
            if claims
                .iter()
                .any(|claim| claim.credential_id != credential_id)
            {
                return Err(anyhow::anyhow!("Claim credential-id mismatch!").into());
            }

            self.claim_repository
                .delete_claims_for_credential(credential_id)
                .await?;

            if !claims.is_empty() {
                self.claim_repository.create_claim_list(claims).await?;
            }
        }

        Ok(())
    }
}

fn get_credential_list_query(query_params: CredentialListQuery) -> Select<credential::Entity> {
    let mut query = credential::Entity::find()
        .select_only()
        .columns([
            credential::Column::Id,
            credential::Column::CreatedDate,
            credential::Column::LastModified,
            credential::Column::IssuanceDate,
            credential::Column::ExpiresAt,
            credential::Column::DeletedAt,
            credential::Column::ConsumedAt,
            credential::Column::RedirectUri,
            credential::Column::Role,
            credential::Column::State,
            credential::Column::Type,
            credential::Column::SuspendEndDate,
            credential::Column::Protocol,
            credential::Column::Profile,
            credential::Column::ParentId,
            credential::Column::KeyId,
            credential::Column::InteractionId,
            credential::Column::HolderIdentifierId,
            credential::Column::IssuerCertificateId,
            credential::Column::CredentialBlobId,
            credential::Column::WalletUnitAttestationBlobId,
            credential::Column::WalletInstanceAttestationBlobId,
            credential::Column::WebhookUrl,
            credential::Column::EmbeddedDisclosurePolicy,
            credential::Column::Ecosystem,
            credential::Column::Format,
        ])
        .join(
            sea_orm::JoinType::InnerJoin,
            credential::Relation::CredentialSchema.def(),
        )
        .column_as(
            credential_schema::Column::CreatedDate,
            "credential_schema_created_date",
        )
        .column_as(
            credential_schema::Column::DeletedAt,
            "credential_schema_deleted_at",
        )
        .column_as(credential_schema::Column::Id, "credential_schema_id")
        .column_as(
            credential_schema::Column::LastModified,
            "credential_schema_last_modified",
        )
        .column_as(credential_schema::Column::Name, "credential_schema_name")
        .column_as(
            credential_schema::Column::KeyStorageSecurity,
            "credential_schema_key_storage_security",
        )
        .column_as(
            credential_schema::Column::OrganisationId,
            "credential_schema_organisation_id",
        )
        .column_as(
            credential_schema::Column::ImportedSourceUrl,
            "credential_schema_imported_source_url",
        )
        .column_as(
            credential_schema::Column::AllowSuspension,
            "credential_schema_allow_suspension",
        )
        .column_as(
            credential_schema::Column::RequiresWalletInstanceAttestation,
            "credential_schema_requires_wallet_instance_attestation",
        )
        .column_as(
            credential_schema::Column::TransactionCodeType,
            "credential_schema_transaction_code_type",
        )
        .column_as(
            credential_schema::Column::TransactionCodeLength,
            "credential_schema_transaction_code_length",
        )
        .column_as(
            credential_schema::Column::TransactionCodeDescription,
            "credential_schema_transaction_code_description",
        )
        .column_as(
            credential_schema::Column::BatchSize,
            "credential_schema_batch_size",
        )
        .column_as(
            credential_schema::Column::AllowRevocation,
            "credential_schema_allow_revocation",
        )
        .column_as(
            credential_schema::Column::EmbeddedDisclosurePolicy,
            "credential_schema_embedded_disclosure_policy",
        )
        .column_as(
            credential_schema::Column::Expiration,
            "credential_schema_expiration",
        )
        .column_as(
            credential_schema::Column::Ecosystem,
            "credential_schema_ecosystem",
        )
        .join(
            JoinType::LeftJoin,
            credential::Relation::IssuerIdentifier.def(),
        )
        .column_as(identifier::Column::Id, "issuer_identifier_id")
        .column_as(
            identifier::Column::CreatedDate,
            "issuer_identifier_created_date",
        )
        .column_as(
            identifier::Column::LastModified,
            "issuer_identifier_last_modified",
        )
        .column_as(identifier::Column::Name, "issuer_identifier_name")
        .column_as(identifier::Column::Type, "issuer_identifier_type")
        .column_as(identifier::Column::IsRemote, "issuer_identifier_is_remote")
        .column_as(identifier::Column::State, "issuer_identifier_state")
        .column_as(
            identifier::Column::OrganisationId,
            "issuer_identifier_organisation_id",
        )
        .column_as(identifier::Column::DidId, "issuer_identifier_did_id")
        .column_as(identifier::Column::KeyId, "issuer_identifier_key_id")
        // list query
        .with_filter_join(&query_params)
        .with_list_query(&query_params);

    if query_params.sorting.is_some() || query_params.pagination.is_some() {
        // fallback ordering
        query = query
            .order_by_desc(credential::Column::CreatedDate)
            .order_by_desc(credential::Column::Id);
    }

    if let Some(include) = query_params.include
        && include.contains(&CredentialListIncludeEntityTypeEnum::LayoutProperties)
    {
        query = query.column_as(
            credential_schema::Column::LayoutProperties,
            "credential_schema_schema_layout_properties",
        );
    }

    query
}

#[autometrics]
#[async_trait::async_trait]
impl CredentialRepository for CredentialProvider {
    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError> {
        let issuer_identifier_id = request
            .issuer_identifier
            .as_ref()
            .map(|identifier| identifier.id());

        let issuer_certificate_id = request.issuer_certificate.as_ref().map(|cert| cert.id());

        let holder_identifier_id = request
            .holder_identifier
            .as_ref()
            .map(|identifier| identifier.id());

        let claims = request.claims.as_ref().await?.to_owned();

        let interaction_id = request
            .interaction
            .as_ref()
            .map(|interaction| interaction.id());

        let key_id = request.key.as_ref().map(|key| key.id());

        if claims.iter().any(|claim| claim.credential_id != request.id) {
            return Err(anyhow::anyhow!("Claim credential-id mismatch!").into());
        }

        let credential_id = request.id;
        let active_model = request_to_active_model(
            &request,
            issuer_identifier_id,
            issuer_certificate_id,
            holder_identifier_id,
            interaction_id,
            key_id,
            request.credential_blob_id,
            request.wallet_unit_attestation_blob_id,
            request.wallet_instance_attestation_blob_id,
        );

        self.db
            .tx_with_config(
                async {
                    active_model
                        .insert(&self.db)
                        .await
                        .map_err(|e| match e.sql_err() {
                            Some(SqlErr::UniqueConstraintViolation(_)) => {
                                DataLayerError::AlreadyExists
                            }
                            _ => DataLayerError::Db(e.into()),
                        })?;

                    if !claims.is_empty() {
                        self.claim_repository.create_claim_list(claims).await?;
                    }

                    Ok::<_, DataLayerError>(())
                }
                .boxed(),
                // In isolation mode "read committed" InnoDB will _not_ create gap locks. Given there
                // are multiple unique indexes, this is necessary to avoid deadlocks during parallel
                // inserts.
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await??;

        Ok(credential_id)
    }

    async fn delete_credentials(&self, credentials: &[Credential]) -> Result<(), DataLayerError> {
        let ids: Vec<_> = credentials.iter().map(|c| c.id).collect();
        credential::Entity::update_many()
            .filter(credential::Column::Id.is_in(ids))
            .set(credential::ActiveModel {
                deleted_at: Set(Some(one_core::clock::now_utc())),
                ..Default::default()
            })
            .exec(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        Ok(())
    }

    async fn get_credential(&self, id: &CredentialId) -> Result<Credential, DataLayerError> {
        let credential = credential::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::Credential,
                id: (*id).into(),
            })?;

        Ok(self.credential_model_to_repository_model(credential))
    }

    async fn get_credentials_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<Vec<Credential>, DataLayerError> {
        let credentials = credential::Entity::find()
            .filter(credential::Column::InteractionId.eq(interaction_id.to_string()))
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(self.credentials_to_repository(credentials))
    }

    async fn get_credential_list(
        &self,
        query_params: CredentialListQuery,
    ) -> Result<GetCredentialList, DataLayerError> {
        let limit = query_params
            .pagination
            .as_ref()
            .map(|pagination| pagination.page_size as _);

        let query = get_credential_list_query(query_params);

        let (items_count, credentials) = tokio::join!(
            query.to_owned().count(&self.db),
            query
                .into_model::<CredentialListEntityModel>()
                .all(&self.db)
        );

        let items_count = items_count.map_err(|e| DataLayerError::Db(e.into()))?;
        let credentials = credentials.map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(GetCredentialList {
            values: credentials_to_repository(
                credentials,
                &self.cloned(),
                &self.claim_repository,
                &self.organisation_repository,
                &self.did_repository,
                &self.key_repository,
                &self.certificate_repository,
                &self.identifier_repository,
                &self.interaction_repository,
                &self.trust_information_repository,
                &self.db,
            )?,
            total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
            total_items: items_count,
        })
    }

    async fn update_credential(
        &self,
        credential_id: CredentialId,
        request: UpdateCredentialRequest,
    ) -> Result<(), DataLayerError> {
        let holder_identifier_id = match request.holder_identifier_id {
            None => Unchanged(Default::default()),
            Some(identifier_id) => Set(Some(identifier_id)),
        };

        let issuer_identifier_id = match request.issuer_identifier_id {
            None => Unchanged(Default::default()),
            Some(identifier_id) => Set(Some(identifier_id)),
        };

        let issuer_certificate_id = match request.issuer_certificate_id {
            None => Unchanged(Default::default()),
            Some(certificate_id) => Set(Some(certificate_id)),
        };

        let credential_blob_id = match request.credential_blob_id {
            None => Unchanged(Default::default()),
            Some(blob_id) => Set(Some(blob_id)),
        };

        let interaction_id = match request.interaction {
            None => Unchanged(Default::default()),
            Some(interaction_id) => Set(Some(interaction_id)),
        };

        let key_id = match request.key {
            None => Unchanged(Default::default()),
            Some(key_id) => Set(Some(key_id)),
        };

        let redirect_uri = match request.redirect_uri {
            None => Unchanged(Default::default()),
            Some(redirect_uri) => Set(redirect_uri),
        };

        let suspend_end_date = from_clearable(request.suspend_end_date);
        let consumed_at = from_clearable(request.consumed_at);

        let state = match request.state {
            None => NotSet,
            Some(state) => Set(state.into()),
        };

        let issuance_date = match request.issuance_date {
            None => Unchanged(Default::default()),
            Some(issuance_date) => Set(issuance_date.into()),
        };

        let expires_at = match request.expires_at {
            None => Unchanged(Default::default()),
            Some(expires_at) => Set(Some(expires_at)),
        };

        let wallet_unit_attestation_blob_id = match request.wallet_unit_attestation_blob_id {
            None => Unchanged(Default::default()),
            Some(blob_id) => Set(Some(blob_id)),
        };

        let wallet_instance_attestation_blob_id = match request.wallet_instance_attestation_blob_id
        {
            None => Unchanged(Default::default()),
            Some(blob_id) => Set(Some(blob_id)),
        };

        let update_model = credential::ActiveModel {
            id: Unchanged(credential_id),
            last_modified: Set(one_core::clock::now_utc()),
            issuance_date,
            expires_at,
            holder_identifier_id,
            issuer_identifier_id,
            issuer_certificate_id,
            interaction_id,
            key_id,
            redirect_uri,
            suspend_end_date,
            consumed_at,
            state,
            credential_blob_id,
            wallet_unit_attestation_blob_id,
            wallet_instance_attestation_blob_id,
            ..Default::default()
        };

        self.update_claims(credential_id, request.claims).await?;

        update_model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn get_credentials_by_claim_names(
        &self,
        claim_names: Vec<String>,
    ) -> Result<Vec<Credential>, DataLayerError> {
        let credentials = credential::Entity::find()
            .join(JoinType::InnerJoin, credential::Relation::Claim.def())
            .join(
                JoinType::InnerJoin,
                claim::Relation::ClaimSchema
                    .def()
                    .on_condition(move |_left, _right| {
                        Expr::col((claim_schema::Entity, claim_schema::Column::Key))
                            .is_in(&claim_names)
                            .into_condition()
                    }),
            )
            .distinct()
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(self.credentials_to_repository(credentials))
    }

    async fn delete_credential_blobs(
        &self,
        request: HashSet<CredentialId>,
    ) -> Result<(), DataLayerError> {
        credential::Entity::update_many()
            .filter(credential::Column::Id.is_in(request))
            .set(credential::ActiveModel {
                credential_blob_id: Set(None),
                ..Default::default()
            })
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;
        Ok(())
    }
}
