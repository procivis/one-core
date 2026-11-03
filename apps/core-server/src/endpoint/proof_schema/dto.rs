use one_core::model::proof_schema::ExactProofSchemaFilterColumn;
use one_core::service::error::ServiceError;
use one_core::service::proof_schema::dto::{
    CreateProofSchemaClaimRequestDTO, CreateProofSchemaRequestDTO,
    ExportProofInputSchemaResponseDTO, ExportProofSchemaResponseDTO, GetProofSchemaListItemDTO,
    GetProofSchemaResponseDTO, ImportProofSchemaClaimSchemaDTO, ImportProofSchemaDTO,
    ImportProofSchemaInputSchemaDTO, ImportProofSchemaRequestDTO, ProofClaimSchemaResponseDTO,
    ProofInputSchemaRequestDTO, ProofInputSchemaResponseDTO, ProofSchemaFilterParamsDTO,
    ProofSchemaShareResponseDTO,
};
use one_dto_mapper::{
    From, Into, TryInto, convert_inner, convert_inner_of_inner, try_convert_inner,
};
use proc_macros::{ModifySchema, options_not_nullable};
use serde::{Deserialize, Serialize};
use shared_types::{EcosystemId, OrganisationId, ProofSchemaId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::ListQueryParamsRest;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::credential_schema::dto::{
    CredentialSchemaListItemResponseRestDTO, CredentialSchemaV2ResponseRestDTO,
    ImportCredentialSchemaV2RequestSchemaRestDTO,
};
use crate::serialize::{front_time, front_time_option};

#[options_not_nullable]
#[derive(Clone, Debug, Default, Deserialize, ToSchema, TryInto, ModifySchema)]
#[try_into(T = CreateProofSchemaRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateProofSchemaRequestRestDTO {
    #[schema(min_length = 1)]
    #[try_into(infallible)]
    pub name: String,
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Defines the length of storage of received proofs, in seconds. After
    /// the defined duration, the received proof and its data are deleted
    /// from the system. If 0, the proofs received when using this proof
    /// schema will not be deleted.
    #[try_into(infallible)]
    pub expire_duration: Option<u32>,
    /// Set of all claims to request.
    #[try_into(with_fn = convert_inner, infallible)]
    #[schema(min_items = 1)]
    pub proof_input_schemas: Vec<ProofInputSchemaRequestRestDTO>,
    #[modify_schema(field = ecosystem)]
    #[try_into(infallible, with_fn = convert_inner)]
    pub ecosystem: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Default, Deserialize, ToSchema, Into, ModifySchema)]
#[into(ProofInputSchemaRequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProofInputSchemaRequestRestDTO {
    /// Formatter provider names selected for this input. If omitted, all
    /// formats of the credential schema are selected.
    #[into(with_fn = convert_inner_of_inner)]
    #[modify_schema(field = format)]
    #[schema(min_items = 1)]
    pub formats: Option<Vec<String>>,
    /// ID of the credential schema from which the `claimSchemas` object
    /// is assembled.
    pub credential_schema_id: Uuid,
    /// Defines the set of attributes being requested when making proof
    /// requests using this schema.
    #[into(with_fn = convert_inner)]
    #[schema(min_items = 1)]
    pub claim_schemas: Vec<ClaimProofSchemaRequestRestDTO>,
}

/// Defines the set of attributes being requested when making proof requests
/// using this schema.
#[derive(Clone, Debug, Default, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateProofSchemaClaimRequestDTO)]
pub(crate) struct ClaimProofSchemaRequestRestDTO {
    /// The `id` of the attribute being requested, from the `claims` object.
    pub id: Uuid,
    /// Whether the attribute is required in the proof request.
    pub required: bool,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T=ImportProofSchemaRequestDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ImportProofSchemaRequestRestDTO {
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    pub schema: ImportProofSchemaRestDTO,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T=ImportProofSchemaDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ImportProofSchemaRestDTO {
    #[try_into(infallible)]
    pub id: ProofSchemaId,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    #[try_into(infallible)]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    #[try_into(infallible)]
    pub last_modified: OffsetDateTime,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(infallible)]
    pub imported_source_url: String,
    #[try_into(infallible)]
    pub expire_duration: u32,
    #[try_into(with_fn = try_convert_inner)]
    pub proof_input_schemas: Vec<ImportProofSchemaInputSchemaRestDTO>,
    #[try_into(infallible)]
    pub ecosystem: Option<EcosystemId>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, TryInto, ModifySchema)]
#[try_into(T=ImportProofSchemaInputSchemaDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ImportProofSchemaInputSchemaRestDTO {
    /// Formatter provider names selected for this input. Defaulting
    /// to all formats of the resolved credential schema if omitted.
    #[try_into(with_fn = convert_inner_of_inner, infallible)]
    #[modify_schema(field = format)]
    #[schema(min_items = 1)]
    pub formats: Option<Vec<String>>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub claim_schemas: Vec<ImportProofSchemaClaimSchemaRestDTO>,
    pub credential_schema: ImportCredentialSchemaV2RequestSchemaRestDTO,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(ImportProofSchemaClaimSchemaDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ImportProofSchemaClaimSchemaRestDTO {
    pub id: Uuid,
    pub requested: bool,
    pub required: bool,
    pub key: String,
    #[schema(example = "STRING")]
    pub data_type: String,
    #[into(with_fn = convert_inner)]
    #[serde(default)]
    #[schema(no_recursion)]
    pub claims: Vec<ImportProofSchemaClaimSchemaRestDTO>,
    pub array: bool,
}

// list endpoint
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(ExactProofSchemaFilterColumn)]
pub(crate) enum ExactProofSchemaFilterColumnRestEnum {
    Name,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::proof_schema::SortableProofSchemaColumn")]
pub(crate) enum SortableProofSchemaColumnRestEnum {
    Name,
    CreatedDate,
}

pub(crate) type GetProofSchemaQuery =
    ListQueryParamsRest<ProofSchemasFilterQueryParamsRest, SortableProofSchemaColumnRestEnum>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams, TryInto)]
#[into_params(parameter_in = Query)]
#[try_into(T = ProofSchemaFilterParamsDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetProofSchemaQuery
pub(crate) struct ProofSchemasFilterQueryParamsRest {
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Return only proof schemas with a name starting with this string.
    /// Not case-sensitive.
    #[try_into(infallible)]
    pub name: Option<String>,
    /// Filter by specific UUIDs.
    #[param(rename = "ids[]", inline)]
    #[try_into(infallible)]
    pub ids: Option<Vec<ProofSchemaId>>,
    /// Set which filters apply in an exact way.
    #[try_into(with_fn = convert_inner_of_inner, infallible)]
    #[param(rename = "exact[]", inline)]
    pub exact: Option<Vec<ExactProofSchemaFilterColumnRestEnum>>,
    /// Return only proof schemas which use only the specified credential formats.
    #[param(rename = "formats[]", inline)]
    #[try_into(infallible)]
    pub formats: Option<Vec<String>>,

    #[param(rename = "ecosystems[]", inline)]
    #[try_into(infallible)]
    pub ecosystems: Option<Vec<EcosystemId>>,

    /// Return only proof schemas created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[try_into(infallible)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only proof schemas created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[try_into(infallible)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only proof schemas last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[try_into(infallible)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only proof schemas last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[try_into(infallible)]
    pub last_modified_before: Option<OffsetDateTime>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetProofSchemaListItemDTO)]
pub(crate) struct GetProofSchemaListItemResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time_option")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub deleted_at: Option<OffsetDateTime>,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    /// The duration of storage of received proofs, in seconds. After the defined duration, the received proof and its data are deleted from the system.
    /// If 0, the proofs received when using this proof schema will not be deleted.
    pub expire_duration: u32,
    pub ecosystem: Option<EcosystemId>,
}

// detail endpoint
#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(GetProofSchemaResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetProofSchemaResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub expire_duration: u32,
    pub imported_source_url: Option<String>,
    pub organisation_id: OrganisationId,
    #[from(with_fn = convert_inner)]
    pub proof_input_schemas: Vec<ProofInputSchemaResponseRestDTO>,
    pub ecosystem: Option<EcosystemId>,
}

/// The set of attributes being requested when using this proof schema.
#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProofClaimSchemaResponseDTO)]
pub(crate) struct ProofClaimSchemaResponseRestDTO {
    pub id: Uuid,
    /// Marking attributes that are targeted with proof request
    pub requested: bool,
    /// Requested as mandatory or optional
    pub required: bool,
    pub key: String,
    /// The type of data accepted for this attribute.
    #[schema(example = "STRING")]
    pub data_type: String,
    #[from(with_fn = convert_inner)]
    #[schema(no_recursion)]
    pub claims: Vec<ProofClaimSchemaResponseRestDTO>,
    pub array: bool,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProofInputSchemaResponseDTO)]
pub(crate) struct ProofInputSchemaResponseRestDTO {
    /// Formatter provider names saved for this proof input.
    #[from(with_fn = convert_inner)]
    #[schema(min_items = 1, example = json!(["SD_JWT_VC"]))]
    pub formats: Vec<String>,
    /// Defines the set of attributes being requested when making proof requests using this schema.
    #[from(with_fn = convert_inner)]
    pub claim_schemas: Vec<ProofClaimSchemaResponseRestDTO>,
    pub credential_schema: CredentialSchemaListItemResponseRestDTO,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProofSchemaShareResponseDTO)]
pub(crate) struct ProofSchemaShareResponseRestDTO {
    pub url: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(ExportProofSchemaResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExportProofSchemaResponseRestDTO {
    pub id: ProofSchemaId,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub expire_duration: u32,
    pub imported_source_url: Option<String>,
    #[from(with_fn = convert_inner)]
    pub proof_input_schemas: Vec<ExportProofInputSchemaResponseRestDTO>,
    pub ecosystem: Option<EcosystemId>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ExportProofInputSchemaResponseDTO)]
pub(crate) struct ExportProofInputSchemaResponseRestDTO {
    /// Formatter provider names saved for this proof input.
    #[from(with_fn = convert_inner)]
    #[schema(min_items = 1, example = json!(["SD_JWT_VC"]))]
    pub formats: Vec<String>,
    /// Defines the set of attributes being requested when making proof requests using this schema.
    #[from(with_fn = convert_inner)]
    pub claim_schemas: Vec<ProofClaimSchemaResponseRestDTO>,
    pub credential_schema: CredentialSchemaV2ResponseRestDTO,
}

#[cfg(test)]
mod test {
    use shared_types::i18n::I18nString;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::endpoint::credential_schema::dto::{
        CredentialClaimSchemaTranslationsRestDTO, CredentialClaimSchemaV2ResponseRestDTO,
        CredentialSchemaBackgroundPropertiesRestDTO, CredentialSchemaCodePropertiesRestDTO,
        CredentialSchemaCodeTypeRestEnum, CredentialSchemaFormatResponseRestDTO,
        CredentialSchemaLayoutPropertiesRestDTO, CredentialSchemaLogoPropertiesRestDTO,
        CredentialSchemaTranslationsRestDTO, CredentialSchemaWalletAttestationRestDTO,
        KeyStorageSecurityRestEnum,
    };

    #[test]
    fn test_shared_schema_deserializes_into_import_schema() {
        let shared = ExportProofSchemaResponseRestDTO {
            id: Uuid::new_v4().into(),
            created_date: one_core::clock::now_utc(),
            last_modified: one_core::clock::now_utc(),
            name: "name".to_string(),
            expire_duration: 42,
            imported_source_url: Some("imported_source_url".to_string()),
            ecosystem: Some("EUDI".into()),
            proof_input_schemas: vec![ExportProofInputSchemaResponseRestDTO {
                formats: vec!["format".into()],
                claim_schemas: vec![ProofClaimSchemaResponseRestDTO {
                    id: Uuid::new_v4(),
                    requested: true,
                    required: true,
                    key: "key".to_string(),
                    data_type: "data_type".to_string(),
                    claims: vec![],
                    array: true,
                }],
                credential_schema: CredentialSchemaV2ResponseRestDTO {
                    id: Uuid::new_v4().into(),
                    created_date: one_core::clock::now_utc(),
                    last_modified: one_core::clock::now_utc(),
                    name: "name".to_string(),
                    formats: vec![CredentialSchemaFormatResponseRestDTO {
                        format: "format".into(),
                        ecosystem_schema_id: "schema_id".to_string(),
                        dcql: None,
                    }],
                    imported_source_url: "imported_source_url".to_string(),
                    layout_properties: Some(CredentialSchemaLayoutPropertiesRestDTO {
                        background: Some(CredentialSchemaBackgroundPropertiesRestDTO {
                            color: Some("color".to_string()),
                            image: None,
                        }),
                        logo: Some(CredentialSchemaLogoPropertiesRestDTO {
                            font_color: Some("font_color".to_string()),
                            background_color: Some("background_color".to_string()),
                            image: None,
                        }),
                        primary_attribute: Some("primary_attribute".to_string()),
                        secondary_attribute: Some("secondary_attribute".to_string()),
                        picture_attribute: Some("picture_attribute".to_string()),
                        code: Some(CredentialSchemaCodePropertiesRestDTO {
                            attribute: "attribute".to_string(),
                            r#type: CredentialSchemaCodeTypeRestEnum::Barcode,
                        }),
                    }),
                    allow_suspension: true,
                    allow_revocation: Some(true),
                    translations: CredentialSchemaTranslationsRestDTO {
                        name: I18nString(std::collections::BTreeMap::from([(
                            "en".to_string(),
                            "name".to_string(),
                        )])),
                        description: None,
                    },
                    ecosystem: Some("EUDI".into()),
                    organisation_id: Uuid::new_v4().into(),
                    claims: vec![CredentialClaimSchemaV2ResponseRestDTO {
                        id: Uuid::new_v4().into(),
                        created_date: one_core::clock::now_utc(),
                        last_modified: one_core::clock::now_utc(),
                        key: "attribute".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: false,
                        claims: vec![],
                        mappings: None,
                        translations: CredentialClaimSchemaTranslationsRestDTO {
                            name: I18nString(std::collections::BTreeMap::from([(
                                "en".to_string(),
                                "attribute".to_string(),
                            )])),
                        },
                    }],
                    wallet_attestation: CredentialSchemaWalletAttestationRestDTO {
                        require_instance_attestation: true,
                        key_storage_security_level: Some(KeyStorageSecurityRestEnum::Basic),
                        preferred_key_storage_attestation_lifetime: None,
                        preferred_instance_attestation_lifetime: None,
                        monitor_credential_lifetime: false,
                    },
                    batch_size: None,
                    transaction_code: None,
                    embedded_disclosure_policy: None,
                    expiration: None,
                },
            }],
        };

        let serialized = serde_json::to_value(shared).unwrap();

        let imported =
            serde_json::from_value::<ImportProofSchemaRestDTO>(serialized.clone()).unwrap();
        assert_eq!(
            imported.proof_input_schemas[0].formats,
            Some(vec!["format".into()])
        );
        let imported: ImportProofSchemaDTO = imported.try_into().unwrap();
        assert_eq!(
            imported.proof_input_schemas[0].formats,
            Some(vec!["format".into()])
        );
        let mut legacy = serialized;
        legacy["proofInputSchemas"][0]
            .as_object_mut()
            .unwrap()
            .remove("formats");
        let imported = serde_json::from_value::<ImportProofSchemaDTO>(legacy).unwrap();
        assert_eq!(imported.proof_input_schemas[0].formats, None);
    }
}
