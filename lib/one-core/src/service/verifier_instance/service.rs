use std::str::FromStr;

use futures::FutureExt;
use one_dto_mapper::convert_inner;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::VerifierInstanceService;
use super::dto::{RegisterVerifierInstanceRequestDTO, RegisterVerifierInstanceResponseDTO};
use super::error::VerifierInstanceServiceError;
use crate::error::ContextWithErrorCode;
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::verifier_instance::VerifierInstance;
use crate::proto::session_provider::SessionExt;
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
}
