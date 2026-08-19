//! Assembles the ecosystem metadata advertised by the wallet- and
//! verifier-provider SSI endpoints.
//!
//! A provider advertises the ecosystems selected by the organisation owning it,
//! together with the entities of that organisation - trust collections and
//! schemas - belonging to those ecosystems.

use std::collections::HashMap;

use serde::Deserialize;
use shared_types::EcosystemId;

use crate::config::core_config::{
    ConfigEntryDisplay, ConfigExt, CoreConfig, EcosystemProviderType, Fields,
};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::model::credential_schema::CredentialSchema;
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::model::organisation::Organisation;
use crate::model::proof_schema::ProofSchema;
use crate::model::trust_collection::{TrustCollection, TrustCollectionFilterValue};
use crate::proto::trust_collection::dto::RemoteTrustCollectionInfoDTO;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::service::credential_schema::dto::CredentialSchemaFilterValue;
use crate::service::error::ServiceError;
use crate::service::managed_instance::dto::{
    DisplayNameDTO, EcosystemMetadataDTO, EcosystemTrustCollectionDTO, ProviderTrustCollectionDTO,
};
use crate::service::managed_instance::mapper::params_into_display_names;
use crate::service::proof_schema::dto::ProofSchemaFilterValue;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcosystemPublicParams {
    #[serde(default)]
    description: HashMap<String, String>,
    logo: String,
    /// Whether instance providers of this ecosystem should have their trust
    /// collections subscribed to unless the user selected otherwise.
    #[serde(default)]
    instance_provider_default_selected: bool,
}

/// Repositories needed to collect the entities belonging to an ecosystem.
///
/// `proof_schemas` is only provided by the verifier provider, wallet providers
/// do not advertise proof schemas.
pub(crate) struct EcosystemEntityRepositories<'a> {
    pub trust_collections: &'a dyn TrustCollectionRepository,
    pub credential_schemas: &'a dyn CredentialSchemaRepository,
    pub proof_schemas: Option<&'a dyn ProofSchemaRepository>,
}

/// Builds the metadata of the `ecosystems` advertised by a provider.
///
/// Providers not associated with an organisation advertise no ecosystems.
pub(crate) async fn ecosystem_metadata(
    config: &CoreConfig,
    organisation: Option<&Organisation>,
    repositories: EcosystemEntityRepositories<'_>,
) -> Result<Vec<EcosystemMetadataDTO>, NestedError> {
    let Some(organisation) = organisation else {
        return Ok(vec![]);
    };

    let ecosystems = &organisation.configuration.selected_ecosystems;
    if ecosystems.is_empty() {
        return Ok(vec![]);
    }

    let entities = ecosystem_entities(ecosystems, organisation, repositories).await?;

    let mut result = Vec::with_capacity(ecosystems.len());
    for ecosystem in ecosystems {
        let fields = config
            .ecosystem
            .get_if_enabled(ecosystem)
            .error_while(format!(
                "resolving ecosystem `{ecosystem}` selected by organisation `{}`",
                organisation.id
            ))?;

        let display = ecosystem_display(fields)?;

        result.push(EcosystemMetadataDTO {
            name: ecosystem.to_owned(),
            display_name: display.display_name,
            description: display.description,
            logo: display.logo,
            default_selected: display.default_selected,
            trust_collections: entities
                .trust_collections
                .iter()
                .filter(|collection| &collection.ecosystem == ecosystem)
                .map(|collection| EcosystemTrustCollectionDTO {
                    id: collection.id,
                    name: collection.name.to_owned(),
                })
                .collect(),
            credential_schemas: entities
                .credential_schemas
                .iter()
                .filter(|schema| schema.ecosystem.as_ref() == Some(ecosystem))
                .map(|schema| schema.imported_source_url.to_owned())
                .collect(),
            proof_schemas: entities
                .proof_schemas
                .iter()
                .filter(|schema| schema.ecosystem.as_ref() == Some(ecosystem))
                .filter_map(|schema| schema.imported_source_url.to_owned())
                .collect(),
        });
    }

    Ok(result)
}

/// The display properties a configured ecosystem is presented with, independent of
/// the provider advertising it.
pub(crate) struct EcosystemDisplay {
    pub display_name: Vec<DisplayNameDTO>,
    pub description: Vec<DisplayNameDTO>,
    pub logo: String,
    pub default_selected: bool,
}

/// Reads the display properties of an ecosystem from its configuration entry.
pub(crate) fn ecosystem_display(
    fields: &Fields<EcosystemProviderType>,
) -> Result<EcosystemDisplay, NestedError> {
    let public: EcosystemPublicParams = fields
        .params
        .as_ref()
        .and_then(|params| params.public.clone())
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| ServiceError::MappingError(e.to_string()))
        .error_while("deserializing ecosystem public params")?
        .unwrap_or_default();

    let display_name = match &fields.display {
        ConfigEntryDisplay::Translated(map) => map.to_owned(),
        ConfigEntryDisplay::TranslationId(_) => HashMap::new(),
    };

    Ok(EcosystemDisplay {
        display_name: params_into_display_names(display_name),
        description: params_into_display_names(public.description),
        logo: public.logo,
        default_selected: public.instance_provider_default_selected,
    })
}

/// Flattens the trust collections of all ecosystems into the provider-level
/// list. The display properties of the owning ecosystem stand in for the ones
/// previously configured per collection.
pub(crate) fn provider_trust_collections(
    ecosystems: &[EcosystemMetadataDTO],
) -> Vec<ProviderTrustCollectionDTO> {
    ecosystems
        .iter()
        .flat_map(|ecosystem| {
            ecosystem
                .trust_collections
                .iter()
                .map(|collection| ProviderTrustCollectionDTO {
                    id: collection.id,
                    name: collection.name.to_owned(),
                    logo: ecosystem.logo.to_owned(),
                    display_name: ecosystem.display_name.to_owned(),
                    description: ecosystem.description.to_owned(),
                    default_selected: ecosystem.default_selected,
                })
        })
        .collect()
}

/// Flattens the trust collections of all ecosystems advertised by a remote
/// provider, keeping track of the ecosystem each collection belongs to.
pub(crate) fn remote_trust_collections(
    ecosystems: &[EcosystemMetadataDTO],
) -> Vec<RemoteTrustCollectionInfoDTO> {
    ecosystems
        .iter()
        .flat_map(|ecosystem| {
            ecosystem
                .trust_collections
                .iter()
                .map(|collection| RemoteTrustCollectionInfoDTO {
                    id: collection.id,
                    name: collection.name.to_owned(),
                    ecosystem: ecosystem.name.to_owned(),
                })
        })
        .collect()
}

struct EcosystemEntities {
    trust_collections: Vec<TrustCollection>,
    credential_schemas: Vec<CredentialSchema>,
    proof_schemas: Vec<ProofSchema>,
}

async fn ecosystem_entities(
    ecosystems: &[EcosystemId],
    organisation: &Organisation,
    repositories: EcosystemEntityRepositories<'_>,
) -> Result<EcosystemEntities, NestedError> {
    let trust_collections = repositories
        .trust_collections
        .list(ListQuery {
            filtering: Some(
                TrustCollectionFilterValue::OrganisationId {
                    id: organisation.id,
                    include_inherited_collections: true,
                }
                .condition()
                    & TrustCollectionFilterValue::Ecosystems(ecosystems.to_owned()),
            ),
            ..Default::default()
        })
        .await
        .error_while("getting ecosystem trust collections")?
        .values;

    let credential_schemas = repositories
        .credential_schemas
        .get_credential_schema_list(ListQuery {
            filtering: Some(
                CredentialSchemaFilterValue::OrganisationId(organisation.id).condition()
                    & CredentialSchemaFilterValue::Ecosystems(ecosystems.to_owned()),
            ),
            ..Default::default()
        })
        .await
        .error_while("getting ecosystem credential schemas")?
        .values;

    let proof_schemas = match repositories.proof_schemas {
        None => vec![],
        Some(repository) => {
            repository
                .get_proof_schema_list(ListQuery {
                    filtering: Some(
                        ProofSchemaFilterValue::OrganisationId(organisation.id).condition()
                            & ProofSchemaFilterValue::Ecosystems(ecosystems.to_owned()),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("getting ecosystem proof schemas")?
                .values
        }
    };

    Ok(EcosystemEntities {
        trust_collections,
        credential_schemas,
        proof_schemas,
    })
}
