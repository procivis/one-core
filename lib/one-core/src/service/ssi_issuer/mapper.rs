use std::collections::HashMap;
use std::collections::hash_map::Entry;

use serde_json::Value;
use url::Url;

use super::dto::{
    JsonLDContextDTO, JsonLDInlineEntityDTO, SdJwtVcClaimDTO, SdJwtVcClaimDisplayDTO,
    SdJwtVcClaimSd, SdJwtVcDisplayMetadataDTO, SdJwtVcRenderingDTO, SdJwtVcSimpleRenderingDTO,
    SdJwtVcSimpleRenderingLogoDTO, SdJwtVcTypeMetadataResponseDTO,
};
use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::model::credential_schema::{
    Arrayed, CredentialSchema, CredentialSchemaClaim, CredentialSchemaClaimsNestedTypeView,
    CredentialSchemaClaimsNestedView,
};
use crate::service::credential_schema::dto::CredentialSchemaLayoutPropertiesResponseDTO;
use crate::service::error::ServiceError;
use crate::service::ssi_issuer::dto::{
    JsonLDEntityDTO, JsonLDNestedContextDTO, JsonLDNestedEntityDTO,
};

impl Default for JsonLDContextDTO {
    fn default() -> Self {
        Self {
            version: Some(1.1),
            protected: true,
            id: "@id".to_string(),
            r#type: "@type".to_string(),
            entities: HashMap::default(),
        }
    }
}

pub(crate) fn generate_jsonld_context_response(
    claim_schemas: &Vec<CredentialSchemaClaim>,
    base_url: &str,
) -> Result<HashMap<String, JsonLDEntityDTO>, ServiceError> {
    let mut entities: HashMap<String, JsonLDEntityDTO> = HashMap::new();
    for claim_schema in claim_schemas {
        // Metadata claims are not part of our JSON-LD context
        if claim_schema.schema.data_type != "OBJECT" && !claim_schema.schema.metadata {
            let key_parts: Vec<&str> = claim_schema.schema.key.split(NESTED_CLAIM_MARKER).collect();
            insert_claim(&mut entities, &key_parts, base_url, 0)?;
        }
    }
    Ok(entities)
}

fn insert_claim(
    current_claim: &mut HashMap<String, JsonLDEntityDTO>,
    key_parts: &Vec<&str>,
    base_url: &str,
    index: usize,
) -> Result<(), ServiceError> {
    if index >= key_parts.len() {
        return Ok(());
    }

    let part = key_parts[index].to_string();

    let nested_claim = match current_claim.entry(part.clone()) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            entry.insert(JsonLDEntityDTO::NestedObject(JsonLDNestedEntityDTO {
                id: get_url_with_fragment(base_url, &part)?,
                context: JsonLDNestedContextDTO {
                    protected: true,
                    id: "@id".to_string(),
                    r#type: "@type".to_string(),
                    entities: HashMap::new(),
                },
            }))
        }
    };

    if let JsonLDEntityDTO::NestedObject(nested) = nested_claim {
        insert_claim(&mut nested.context.entities, key_parts, base_url, index + 1)?;
    }

    if index == key_parts.len() - 1 {
        let reference_claim = JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
            id: get_url_with_fragment(base_url, &part)?,
            r#type: None,
            context: None,
        });
        current_claim.insert(part, reference_claim);
    }

    Ok(())
}

pub(crate) fn get_url_with_fragment(
    base_url: &str,
    fragment: &str,
) -> Result<String, ServiceError> {
    let mut url = Url::parse(base_url).map_err(|e| ServiceError::MappingError(e.to_string()))?;
    // We need to url encode the fragment in case `#` is used in a claim name
    url.set_fragment(Some(&urlencoding::encode(fragment)));
    Ok(url.to_string())
}

pub(crate) fn credential_schema_to_sd_jwt_vc_metadata(
    vct_type: String,
    schema: CredentialSchema,
) -> Result<SdJwtVcTypeMetadataResponseDTO, ServiceError> {
    let background_color: Option<String> = schema.layout_properties.as_ref().map(|props| {
        props
            .background
            .iter()
            .flat_map(|bg| bg.color.clone())
            .collect()
    });
    let logo = vct_logo_from_schema(&schema)?;
    let rendering = SdJwtVcRenderingDTO {
        simple: Some(SdJwtVcSimpleRenderingDTO {
            logo,
            background_color, // defaults to None
            text_color: Some("#FFFFFF".to_string()),
        }),
    };
    let display_en_us = SdJwtVcDisplayMetadataDTO {
        lang: "en-US".to_string(),
        name: schema.name,
        rendering: Some(rendering),
    };

    let nested_claims =
        CredentialSchemaClaimsNestedView::try_from(schema.claim_schemas.unwrap_or_default())?;
    let claims = vct_claims_from_nested_view(nested_claims);
    Ok(SdJwtVcTypeMetadataResponseDTO {
        vct: schema.schema_id,
        name: Some(vct_type),
        display: vec![display_en_us],
        claims,
        layout_properties: schema
            .layout_properties
            .map(CredentialSchemaLayoutPropertiesResponseDTO::from),
        schema: None,
        schema_uri: None,
    })
}

fn vct_claims_from_nested_view(
    nested_claims: CredentialSchemaClaimsNestedView,
) -> Vec<SdJwtVcClaimDTO> {
    let mut vct_claims = vec![];
    vct_claims_from_prefix_and_fields(&mut vct_claims, &[], nested_claims.fields);

    // Sort claims in order to make VCT metadata deterministic
    vct_claims.sort_by(|a, b| {
        let a_stringified = a
            .path
            .iter()
            .map(|val| format!("{val}"))
            .collect::<Vec<_>>();
        let b_stringified = b
            .path
            .iter()
            .map(|val| format!("{val}"))
            .collect::<Vec<_>>();
        a_stringified.cmp(&b_stringified)
    });
    vct_claims
}

fn vct_claims_from_prefix_and_fields(
    accumulator: &mut Vec<SdJwtVcClaimDTO>,
    prefix: &[Value],
    fields: HashMap<String, Arrayed<CredentialSchemaClaimsNestedTypeView>>,
) {
    for (name, claim) in fields {
        let mut new_prefix = prefix.to_vec();
        new_prefix.push(Value::String(name.to_string()));

        let claim = match claim {
            Arrayed::InArray(array_claim) => {
                accumulator.push(vct_claim_from_path_label(new_prefix.clone(), name));

                // push null to match all array elements when addressing nested claims
                // see https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-05.html#name-claim-path
                new_prefix.push(Value::Null);
                array_claim
            }
            Arrayed::Single(single_claim) => {
                accumulator.push(vct_claim_from_path_label(new_prefix.clone(), name));
                single_claim
            }
        };

        match claim {
            CredentialSchemaClaimsNestedTypeView::Field(_) => {} // nothing further to do
            CredentialSchemaClaimsNestedTypeView::Object(object_claim) => {
                vct_claims_from_prefix_and_fields(
                    accumulator,
                    new_prefix.as_slice(),
                    object_claim.fields,
                );
            }
        }
    }
}

fn vct_claim_from_path_label(path: Vec<Value>, label: String) -> SdJwtVcClaimDTO {
    SdJwtVcClaimDTO {
        path,
        display: vec![SdJwtVcClaimDisplayDTO {
            lang: "en-US".to_string(),
            label,
        }],
        sd: Some(SdJwtVcClaimSd::Allowed),
    }
}

fn vct_logo_from_schema(
    schema: &CredentialSchema,
) -> Result<Option<SdJwtVcSimpleRenderingLogoDTO>, ServiceError> {
    Ok(schema
        .layout_properties
        .iter()
        .flat_map(|layout| &layout.logo)
        .flat_map(|logo| &logo.image)
        .map(|s| Url::try_from(s.as_str()))
        .next()
        .transpose()
        .map_err(|err| ServiceError::MappingError(format!("failed to parse logo URL: {err}")))?
        .map(|uri| SdJwtVcSimpleRenderingLogoDTO {
            uri,
            alt_text: None,
        }))
}
