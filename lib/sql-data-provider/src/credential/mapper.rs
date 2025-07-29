use one_core::model::credential::{Credential, CredentialRole, SortableCredentialColumn};
use one_core::model::credential_schema::{CredentialSchema, LayoutType};
use one_core::model::identifier::Identifier;
use one_core::model::interaction::InteractionId;
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::revocation_list::RevocationListId;
use one_core::repository::error::DataLayerError;
use one_core::service::credential::dto::CredentialFilterValue;
use one_dto_mapper::convert_inner;
use sea_orm::sea_query::SimpleExpr;
use sea_orm::sea_query::query::IntoCondition;
use sea_orm::{ColumnTrait, IntoSimpleExpr, JoinType, RelationTrait, Set};
use shared_types::{BlobId, CertificateId, IdentifierId, KeyId};

use crate::credential::entity_model::CredentialListEntityModel;
use crate::entity::{claim, credential, credential_schema, identifier};
use crate::list_query_generic::{
    IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation,
    get_blob_match_condition, get_comparison_condition, get_equals_condition,
    get_string_match_condition,
};

impl IntoSortingColumn for SortableCredentialColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::CreatedDate => credential::Column::CreatedDate.into_simple_expr(),
            Self::SchemaName => credential_schema::Column::Name.into_simple_expr(),
            Self::Issuer => identifier::Column::Name.into_simple_expr(),
            Self::State => credential::Column::State.into_simple_expr(),
        }
    }
}

impl IntoFilterCondition for CredentialFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::CredentialSchemaName(string_match) => {
                get_string_match_condition(credential_schema::Column::Name, string_match)
            }
            Self::ClaimName(string_match) => {
                get_string_match_condition(claim::Column::Path, string_match)
            }
            Self::ClaimValue(string_match) => {
                get_blob_match_condition(claim::Column::Value, string_match, 255)
            }
            Self::OrganisationId(organisation_id) => get_equals_condition(
                credential_schema::Column::OrganisationId,
                organisation_id.to_string(),
            ),
            Self::Role(role) => get_equals_condition(credential::Column::Role, role.as_ref()),
            Self::CredentialIds(ids) => credential::Column::Id.is_in(ids.iter()).into_condition(),
            Self::State(states) => credential::Column::State
                .is_in(
                    states
                        .into_iter()
                        .map(credential::CredentialState::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::SuspendEndDate(comparison) => {
                get_comparison_condition(credential::Column::SuspendEndDate, comparison)
            }
            Self::Profile(string_match) => {
                get_string_match_condition(credential::Column::Profile, string_match)
            }
        }
    }
}

impl IntoJoinRelations for CredentialFilterValue {
    fn get_join(&self) -> Vec<JoinRelation> {
        match self {
            // add claims if filtering by claim name/value
            Self::ClaimName(_) | Self::ClaimValue(_) => {
                vec![JoinRelation {
                    join_type: JoinType::LeftJoin,
                    relation_def: credential::Relation::Claim.def(),
                    alias: None,
                }]
            }
            _ => vec![],
        }
    }
}

impl From<credential::Model> for Credential {
    fn from(credential: credential::Model) -> Self {
        Self {
            id: credential.id,
            created_date: credential.created_date,
            issuance_date: credential.issuance_date,
            last_modified: credential.last_modified,
            deleted_at: credential.deleted_at,
            protocol: credential.protocol,
            redirect_uri: credential.redirect_uri,
            role: credential.role.into(),
            state: credential.state.into(),
            suspend_end_date: credential.suspend_end_date,
            profile: credential.profile,
            claims: None,
            issuer_identifier: None,
            issuer_certificate: None,
            holder_identifier: None,
            schema: None,
            interaction: None,
            revocation_list: None,
            key: None,
            credential_blob_id: credential.credential_blob_id,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn request_to_active_model(
    request: &Credential,
    schema: CredentialSchema,
    issuer_identifier_id: Option<IdentifierId>,
    issuer_certificate_id: Option<CertificateId>,
    holder_identifier_id: Option<IdentifierId>,
    interaction_id: Option<InteractionId>,
    revocation_list_id: Option<RevocationListId>,
    key_id: Option<KeyId>,
    credential_blob: Option<BlobId>,
) -> credential::ActiveModel {
    credential::ActiveModel {
        id: Set(request.id),
        credential_schema_id: Set(schema.id),
        created_date: Set(request.created_date),
        last_modified: Set(request.last_modified),
        issuance_date: Set(request.issuance_date),
        deleted_at: Set(request.deleted_at),
        protocol: Set(request.protocol.to_owned()),
        redirect_uri: Set(request.redirect_uri.to_owned()),
        issuer_identifier_id: Set(issuer_identifier_id),
        issuer_certificate_id: Set(issuer_certificate_id),
        holder_identifier_id: Set(holder_identifier_id),
        interaction_id: Set(interaction_id.map(|id| id.to_string())),
        revocation_list_id: Set(revocation_list_id.map(|id| id.to_string())),
        key_id: Set(key_id),
        role: Set(request.role.to_owned().into()),
        state: Set(request.state.into()),
        suspend_end_date: Set(request.suspend_end_date),
        profile: Set(request.profile.clone()),
        credential_blob_id: Set(credential_blob),
    }
}

pub(super) fn credential_list_model_to_repository_model(
    credential: CredentialListEntityModel,
) -> Result<Credential, DataLayerError> {
    let schema_id = credential.credential_schema_id;

    let schema = CredentialSchema {
        id: schema_id,
        deleted_at: credential.credential_schema_deleted_at,
        created_date: credential.credential_schema_created_date,
        last_modified: credential.credential_schema_last_modified,
        wallet_storage_type: convert_inner(credential.credential_schema_wallet_storage_type),
        name: credential.credential_schema_name,
        format: credential.credential_schema_format,
        revocation_method: credential.credential_schema_revocation_method,
        schema_type: credential.credential_schema_schema_type.into(),
        external_schema: credential.credential_schema_external_schema,
        imported_source_url: credential.credential_schema_imported_source_url,
        schema_id: credential.credential_schema_schema_id,
        claim_schemas: None,
        organisation: None,
        // todo: this should be fixed in another ticket
        layout_type: LayoutType::Card,
        layout_properties: credential
            .credential_schema_schema_layout_properties
            .map(|layout_properties| layout_properties.into()),
        allow_suspension: credential.credential_schema_allow_suspension,
    };

    let issuer_identifier = match credential.issuer_identifier_id {
        None => None,
        Some(issuer_identifier_id) => Some(Identifier {
            id: issuer_identifier_id,
            created_date: credential
                .issuer_identifier_created_date
                .ok_or(DataLayerError::MappingError)?,
            last_modified: credential
                .issuer_identifier_last_modified
                .ok_or(DataLayerError::MappingError)?,
            name: credential
                .issuer_identifier_name
                .ok_or(DataLayerError::MappingError)?,
            did: None,
            key: None,
            certificates: None,
            organisation: None,
            r#type: credential
                .issuer_identifier_type
                .ok_or(DataLayerError::MappingError)?
                .into(),
            is_remote: credential
                .issuer_identifier_is_remote
                .ok_or(DataLayerError::MappingError)?,
            state: credential
                .issuer_identifier_state
                .ok_or(DataLayerError::MappingError)?
                .into(),
            deleted_at: None,
        }),
    };

    Ok(Credential {
        id: credential.id,
        created_date: credential.created_date,
        issuance_date: credential.issuance_date,
        last_modified: credential.last_modified,
        deleted_at: credential.deleted_at,
        protocol: credential.protocol,
        redirect_uri: credential.redirect_uri,
        role: credential.role.into(),
        state: credential.state.into(),
        suspend_end_date: credential.suspend_end_date,
        profile: credential.profile,
        claims: None,
        issuer_identifier,
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(schema),
        interaction: None,
        revocation_list: None,
        key: None,
        credential_blob_id: credential.credential_blob_id,
    })
}

pub(super) fn credentials_to_repository(
    credentials: Vec<CredentialListEntityModel>,
) -> Result<Vec<Credential>, DataLayerError> {
    let mut result: Vec<Credential> = Vec::new();
    for credential in credentials.into_iter() {
        result.push(credential_list_model_to_repository_model(credential)?);
    }

    Ok(result)
}

pub(crate) fn target_from_credential(credential: &Credential) -> Option<String> {
    match credential.role {
        CredentialRole::Holder => credential
            .issuer_identifier
            .as_ref()
            .map(|identifier| identifier.id.to_string()),
        CredentialRole::Issuer => credential
            .holder_identifier
            .as_ref()
            .map(|identifier| identifier.id.to_string()),
        CredentialRole::Verifier => None,
    }
}
