use std::collections::HashMap;
use std::collections::hash_map::Entry;

use serde_json::Value;
use url::Url;

use super::dto::{
    JsonLDContextDTO, JsonLDEntityDTO, JsonLDInlineEntityDTO, JsonLDNestedContextDTO,
    JsonLDNestedEntityDTO, SdJwtVcClaimDTO, SdJwtVcClaimDisplayDTO, SdJwtVcClaimSd,
    SdJwtVcDisplayMetadataDTO, SdJwtVcRenderingDTO, SdJwtVcSimpleRenderingDTO,
    SdJwtVcSimpleRenderingLogoDTO, SdJwtVcTypeMetadataResponseDTO,
};
use super::error::IssuerServiceError;
use crate::error::ContextWithErrorCode;
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{
    Arrayed, CredentialSchema, CredentialSchemaClaimsNestedTypeView,
    CredentialSchemaClaimsNestedView,
};
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::service::credential_schema::dto::CredentialSchemaLayoutPropertiesResponseDTO;
use crate::service::ssi_issuer::dto::SdJwtVcSimpleRenderingBackgroundImageDTO;

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
    claim_schemas: &Vec<ClaimSchema>,
    base_url: &str,
    claim_mappings: &Option<Vec<CredentialSchemaFormatClaimSchema>>,
) -> Result<HashMap<String, JsonLDEntityDTO>, IssuerServiceError> {
    let mut entities: HashMap<String, JsonLDEntityDTO> = HashMap::new();
    for claim_schema in claim_schemas {
        // Metadata claims are not part of our JSON-LD context
        if claim_schema.data_type == "OBJECT" || claim_schema.metadata {
            continue;
        }

        let key_path = if let Some(claim_mappings) = claim_mappings
            && let Some(mapping) = claim_mappings
                .iter()
                .find(|m| m.claim_schema_id == claim_schema.id)
        {
            &mapping.technical_key
        } else {
            &claim_schema.key
        };

        let key_parts = key_path.split(NESTED_CLAIM_MARKER).collect();
        insert_claim(&mut entities, &key_parts, base_url, 0)?;
    }
    Ok(entities)
}

fn insert_claim(
    current_claim: &mut HashMap<String, JsonLDEntityDTO>,
    key_parts: &Vec<&str>,
    base_url: &str,
    index: usize,
) -> Result<(), IssuerServiceError> {
    if index >= key_parts.len() {
        return Ok(());
    }

    let Some(part) = key_parts.get(index).map(ToString::to_string) else {
        return Ok(());
    };

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
) -> Result<String, IssuerServiceError> {
    let mut url =
        Url::parse(base_url).map_err(|e| IssuerServiceError::MappingError(e.to_string()))?;
    // We need to url encode the fragment in case `#` is used in a claim name
    url.set_fragment(Some(&urlencoding::encode(fragment)));
    Ok(url.to_string())
}

pub(crate) async fn credential_schema_to_sd_jwt_vc_metadata(
    credential_schema_id: String,
    vct: String,
    schema: CredentialSchema,
) -> Result<SdJwtVcTypeMetadataResponseDTO, IssuerServiceError> {
    let simple_rendering = vct_simple_rendering_from_schema(&schema)?;
    let rendering = simple_rendering.map(|simple| SdJwtVcRenderingDTO {
        simple: Some(simple),
    });
    let display_en_us = SdJwtVcDisplayMetadataDTO {
        locale: "en-US".to_string(),
        name: schema.name,
        description: None,
        rendering,
    };

    let user_claims: Vec<_> = schema
        .claim_schemas
        .as_ref()
        .await?
        .iter()
        .filter(|cs| !cs.metadata)
        .cloned()
        .collect();
    let nested_claims = CredentialSchemaClaimsNestedView::try_from(user_claims)
        .error_while("converting nested claims")?;
    let claims = vct_claims_from_nested_view(nested_claims);
    Ok(SdJwtVcTypeMetadataResponseDTO {
        vct,
        name: Some(credential_schema_id),
        description: None,
        display: vec![display_en_us],
        claims,
        layout_properties: schema
            .layout_properties
            .map(CredentialSchemaLayoutPropertiesResponseDTO::from),
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
            locale: "en-US".to_string(),
            label,
            description: None,
        }],
        mandatory: None,
        sd: Some(SdJwtVcClaimSd::Allowed),
    }
}

fn vct_simple_rendering_from_schema(
    schema: &CredentialSchema,
) -> Result<Option<SdJwtVcSimpleRenderingDTO>, IssuerServiceError> {
    let Some(layout_properties) = &schema.layout_properties else {
        return Ok(None);
    };

    let mut result = SdJwtVcSimpleRenderingDTO {
        logo: None,
        background_image: None,
        background_color: None,
        text_color: None,
    };

    if let Some(logo) = &layout_properties.logo
        && let Some(image) = &logo.image
    {
        let uri = Url::try_from(image.as_str()).map_err(|err| {
            IssuerServiceError::MappingError(format!("failed to parse logo URL: {err}"))
        })?;
        result.logo = Some(SdJwtVcSimpleRenderingLogoDTO {
            uri,
            alt_text: None,
        });
    }

    if let Some(background) = &layout_properties.background {
        if let Some(color) = &background.color {
            result.background_color = Some(color.to_owned());
        }

        if let Some(image) = &background.image {
            let uri = Url::try_from(image.as_str()).map_err(|err| {
                IssuerServiceError::MappingError(format!(
                    "failed to parse background image URL: {err}"
                ))
            })?;
            result.background_image = Some(SdJwtVcSimpleRenderingBackgroundImageDTO { uri });
        }
    }

    Ok(Some(result))
}
