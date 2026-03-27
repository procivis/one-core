use std::sync::Arc;

use dto::{ProviderTrustCollectionDTO, VerifierProviderMetadataResponseDTO};
use error::VerifierProviderError;
use mapper::params_into_display_names;

use crate::error::ContextWithErrorCode;
use crate::model::list_filter::ListFilterValue;
use crate::model::trust_collection::{TrustCollectionFilterValue, TrustCollectionListQuery};
use crate::provider::verifier::provider::VerifierProvider;
use crate::repository::trust_collection_repository::TrustCollectionRepository;

pub mod dto;
pub mod error;
mod mapper;

pub struct VerifierProviderService {
    verifier_provider: Arc<dyn VerifierProvider>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
}

impl VerifierProviderService {
    pub(crate) fn new(
        verifier_provider: Arc<dyn VerifierProvider>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    ) -> Self {
        Self {
            verifier_provider,
            trust_collection_repository,
        }
    }

    pub async fn get_verifier_by_id(
        &self,
        id: &str,
    ) -> Result<VerifierProviderMetadataResponseDTO, VerifierProviderError> {
        let verifier = self
            .verifier_provider
            .get_by_id(id)
            .error_while("getting verifier provider")?;

        let trust_collections = if verifier.trust_collections.is_empty() {
            vec![]
        } else {
            let models = self
                .trust_collection_repository
                .list(TrustCollectionListQuery {
                    filtering: Some(
                        TrustCollectionFilterValue::Ids(
                            verifier.trust_collections.keys().cloned().collect(),
                        )
                        .condition(),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("getting trust collections")?
                .values;

            verifier
                .trust_collections
                .into_iter()
                .map(|(collection_id, params)| {
                    let model = models.iter().find(|m| m.id == collection_id).ok_or(
                        VerifierProviderError::MappingError(format!(
                            "Missing collection {}",
                            collection_id
                        )),
                    )?;

                    Ok(ProviderTrustCollectionDTO {
                        id: collection_id,
                        name: model.name.to_owned(),
                        logo: params.logo,
                        display_name: params_into_display_names(params.display_name),
                        description: params_into_display_names(params.description),
                    })
                })
                .collect::<Result<_, VerifierProviderError>>()?
        };

        Ok(VerifierProviderMetadataResponseDTO {
            verifier_name: verifier.verifier_name,
            app_version: verifier.app_version,
            trust_collections,
            feature_flags: verifier.feature_flags,
        })
    }
}
