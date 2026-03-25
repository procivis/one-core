use std::str::FromStr;

use futures::FutureExt;
use one_dto_mapper::convert_inner;
use shared_types::VerifierInstanceId;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::VerifierInstanceService;
use super::dto::{
    EditVerifierInstanceRequestDTO, RegisterVerifierInstanceRequestDTO,
    RegisterVerifierInstanceResponseDTO,
};
use super::error::VerifierInstanceServiceError;
use crate::error::ContextWithErrorCode;
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::verifier_instance::{VerifierInstance, VerifierInstanceRelations};
use crate::proto::session_provider::SessionExt;
use crate::service::wallet_unit::dto::TrustCollectionsDetailResponseDTO;
use crate::service::wallet_unit::mapper::{
    prepare_trust_collection_info, set_active_trust_collections,
};
use crate::validator::throw_if_org_not_matching_session;

impl VerifierInstanceService {
    pub async fn register_verifier_instance(
        &self,
        request: RegisterVerifierInstanceRequestDTO,
    ) -> Result<RegisterVerifierInstanceResponseDTO, VerifierInstanceServiceError> {
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &Default::default())
            .await
            .error_while("getting organisation")?
            .ok_or(VerifierInstanceServiceError::MissingOrganisation(
                request.organisation_id,
            ))?;

        if organisation.deactivated_at.is_some() {
            return Err(VerifierInstanceServiceError::OrganisationIsDeactivated(
                request.organisation_id,
            ));
        }
        let organisation_id = organisation.id;

        if let Some(verifier_instance) = self
            .verifier_instance_repository
            .get_by_org_id(&request.organisation_id)
            .await
            .error_while("checking presence of verifier instance")?
        {
            return Err(VerifierInstanceServiceError::VerifierInstanceAlreadyExists(
                verifier_instance.id,
            ));
        }

        let verifier_provider_url = Url::from_str(&request.verifier_provider_url)
            .map_err(VerifierInstanceServiceError::InvalidProviderUrl)?;
        let provider_url = verifier_provider_url.origin().ascii_serialization();

        let verifier_provider_metadata_url = {
            let mut url = verifier_provider_url.clone();
            url.path_segments_mut()
                .map_err(|_| {
                    VerifierInstanceServiceError::MappingError("Invalid provider URL".to_string())
                })?
                .clear()
                .push("ssi")
                .push("verifier-provider")
                .push("v1")
                .push(&request.r#type);
            url
        };

        let metadata = self
            .verifier_provider_client
            .get_verifier_provider_metadata(verifier_provider_metadata_url.as_str())
            .await
            .error_while("getting verifier provider metadata")?;

        let now = OffsetDateTime::now_utc();

        let verifier_instance_id = Uuid::new_v4().into();
        let success_log = format!(
            "Registered verifier instance `{}`({verifier_instance_id}) using provider `{provider_url}`",
            metadata.verifier_name
        );

        self.tx_manager
            .tx(async {
                self.verifier_instance_repository
                    .create(VerifierInstance {
                        id: verifier_instance_id,
                        created_date: now,
                        last_modified: now,
                        provider_type: request.r#type,
                        provider_name: metadata.verifier_name.to_owned(),
                        provider_url,
                        organisation: Some(organisation),
                    })
                    .await
                    .error_while("creating verifier instance")?;

                self.history_repository
                    .create_history(History {
                        id: Uuid::new_v4().into(),
                        created_date: now,
                        action: HistoryAction::Created,
                        name: metadata.verifier_name,
                        source: HistorySource::Core,
                        target: None,
                        entity_id: Some(verifier_instance_id.into()),
                        entity_type: HistoryEntityType::VerifierInstance,
                        metadata: None,
                        organisation_id: Some(organisation_id),
                        user: self.session_provider.session().user(),
                    })
                    .await
                    .error_while("creating history")?;

                self.trust_collection_manager
                    .create_empty_trust_collections(
                        &request.verifier_provider_url,
                        convert_inner(metadata.trust_collections),
                        organisation_id,
                    )
                    .await
                    .error_while("creating empty trust collections")?;

                Ok::<_, VerifierInstanceServiceError>(())
            }
            .boxed())
            .await
            .error_while("creating instance")??;

        tracing::info!(message = success_log);
        Ok(RegisterVerifierInstanceResponseDTO {
            id: verifier_instance_id,
        })
    }

    pub async fn get_trust_collections(
        &self,
        id: VerifierInstanceId,
    ) -> Result<TrustCollectionsDetailResponseDTO, VerifierInstanceServiceError> {
        let instance = self
            .verifier_instance_repository
            .get(
                &id,
                &VerifierInstanceRelations {
                    organisation: Some(Default::default()),
                },
            )
            .await
            .error_while("getting verifier instance")?
            .ok_or(VerifierInstanceServiceError::VerifierInstanceNotFound(id))?;

        let organisation =
            instance
                .organisation
                .ok_or(VerifierInstanceServiceError::MappingError(
                    "Missing organisation".to_string(),
                ))?;

        throw_if_org_not_matching_session(&organisation.id, &*self.session_provider)
            .error_while("checking session")?;

        let provider_metadata_url = format!(
            "{}/ssi/verifier-provider/v1/{}",
            instance.provider_url, instance.provider_type
        );
        let metadata = self
            .verifier_provider_client
            .get_verifier_provider_metadata(&provider_metadata_url)
            .await
            .error_while("getting verifier provider metadata")?;

        let trust_collections = prepare_trust_collection_info(
            self.trust_collection_repository.as_ref(),
            self.trust_subscription_repository.as_ref(),
            convert_inner(metadata.trust_collections),
            organisation.id,
        )
        .await
        .error_while("preparing trust collections")?;

        Ok(TrustCollectionsDetailResponseDTO { trust_collections })
    }

    pub async fn edit_verifier_instance(
        &self,
        id: VerifierInstanceId,
        request: EditVerifierInstanceRequestDTO,
    ) -> Result<(), VerifierInstanceServiceError> {
        let instance = self
            .verifier_instance_repository
            .get(
                &id,
                &VerifierInstanceRelations {
                    organisation: Some(Default::default()),
                },
            )
            .await
            .error_while("getting verifier instance")?
            .ok_or(VerifierInstanceServiceError::VerifierInstanceNotFound(id))?;

        let organisation =
            instance
                .organisation
                .ok_or(VerifierInstanceServiceError::MappingError(
                    "Missing organisation".to_string(),
                ))?;

        throw_if_org_not_matching_session(&organisation.id, &*self.session_provider)
            .error_while("checking session")?;

        self.tx_manager
            .tx(async {
                set_active_trust_collections(
                    request.trust_collections,
                    organisation.id,
                    self.trust_collection_repository.as_ref(),
                    self.trust_subscription_repository.as_ref(),
                    self.trust_list_subscription_sync.as_ref(),
                )
                .await
            }
            .boxed())
            .await
            .error_while("updating collections")?
            .error_while("updating collections")?;

        tracing::info!("Modified verifier instance ({id})");
        Ok(())
    }
}
