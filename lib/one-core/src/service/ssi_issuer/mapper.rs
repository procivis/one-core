use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};

use serde_json::Value;
use shared_types::ClaimSchemaId;
use standardized_types::sd_jwt_vc::{
    BackgroundImage, ClaimDisplay, ClaimMetadata, DisplayMetadata, Logo, Rendering,
    SelectiveDisclosure, SimpleRendering,
};
use url::Url;

use super::dto::{
    JsonLDContextDTO, JsonLDEntityDTO, JsonLDInlineEntityDTO, JsonLDNestedContextDTO,
    JsonLDNestedEntityDTO, SdJwtVcDisplayMetadataDTO, SdJwtVcTypeMetadataResponseDTO,
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
use crate::model::localized_text::{LocalizedText, LocalizedTextField};
use crate::service::credential_schema::dto::CredentialSchemaLayoutPropertiesResponseDTO;

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
    default_language: &str,
    swiyu_mode: bool,
) -> Result<SdJwtVcTypeMetadataResponseDTO, IssuerServiceError> {
    let rendering = vct_simple_rendering_from_schema(&schema)?.map(|simple| Rendering {
        simple: Some(simple),
    });
    let schema_translations = schema.translations.as_ref().await?;
    let display = group_translations_by_language(&schema_translations, default_language)
        .into_iter()
        .map(|(locale, texts)| SdJwtVcDisplayMetadataDTO {
            lang: swiyu_mode.then(|| locale.clone()),
            display: DisplayMetadata {
                locale,
                name: texts.name.unwrap_or_else(|| schema.name.clone()),
                description: texts.description,
                rendering: rendering.clone(),
            },
        })
        .collect();

    let user_claims: Vec<_> = schema
        .claim_schemas
        .as_ref()
        .await?
        .iter()
        .filter(|cs| !cs.metadata)
        .cloned()
        .collect();
    let mut claim_translations = HashMap::new();
    for claim in &user_claims {
        let translations = claim.translations.as_ref().await?;
        claim_translations.insert(
            claim.id,
            group_translations_by_language(&translations, default_language),
        );
    }
    let nested_claims = CredentialSchemaClaimsNestedView::try_from(user_claims)
        .error_while("converting nested claims")?;
    let claims = vct_claims_from_nested_view(nested_claims, &claim_translations);
    Ok(SdJwtVcTypeMetadataResponseDTO {
        vct,
        name: Some(credential_schema_id),
        description: None,
        display,
        claims,
        layout_properties: schema
            .layout_properties
            .map(CredentialSchemaLayoutPropertiesResponseDTO::from),
    })
}

/// Display texts of a single language
#[derive(Debug, Default)]
struct LocalizedTexts {
    name: Option<String>,
    description: Option<String>,
}

/// Groups translations by language, sorted by language to keep the VCT metadata deterministic.
/// Without any translations, a single (empty) entry for the default language is returned.
fn group_translations_by_language(
    translations: &[LocalizedText],
    default_language: &str,
) -> BTreeMap<String, LocalizedTexts> {
    let mut by_language: BTreeMap<String, LocalizedTexts> = BTreeMap::new();
    for translation in translations {
        let texts = by_language.entry(translation.lang.clone()).or_default();
        let value = Some(translation.value.clone());
        match translation.field {
            LocalizedTextField::Name => texts.name = value,
            LocalizedTextField::Description => texts.description = value,
            // only used for identifiers
            LocalizedTextField::LogoAltText => {}
        }
    }

    if by_language.is_empty() {
        by_language.insert(default_language.to_owned(), LocalizedTexts::default());
    }
    by_language
}

type ClaimTranslations = HashMap<ClaimSchemaId, BTreeMap<String, LocalizedTexts>>;

fn vct_claims_from_nested_view(
    nested_claims: CredentialSchemaClaimsNestedView,
    claim_translations: &ClaimTranslations,
) -> Vec<ClaimMetadata> {
    let mut vct_claims = vec![];
    vct_claims_from_prefix_and_fields(
        &mut vct_claims,
        &[],
        nested_claims.fields,
        claim_translations,
    );

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
    accumulator: &mut Vec<ClaimMetadata>,
    prefix: &[Value],
    fields: HashMap<String, Arrayed<CredentialSchemaClaimsNestedTypeView>>,
    claim_translations: &ClaimTranslations,
) {
    for (name, claim) in fields {
        let mut new_prefix = prefix.to_vec();
        new_prefix.push(Value::String(name.to_string()));

        let claim = match claim {
            Arrayed::InArray(array_claim) => {
                accumulator.push(vct_claim_metadata(
                    new_prefix.clone(),
                    name,
                    &array_claim,
                    claim_translations,
                ));

                // push null to match all array elements when addressing nested claims
                // see https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-05.html#name-claim-path
                new_prefix.push(Value::Null);
                array_claim
            }
            Arrayed::Single(single_claim) => {
                accumulator.push(vct_claim_metadata(
                    new_prefix.clone(),
                    name,
                    &single_claim,
                    claim_translations,
                ));
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
                    claim_translations,
                );
            }
        }
    }
}

fn vct_claim_metadata(
    path: Vec<Value>,
    name: String,
    claim: &CredentialSchemaClaimsNestedTypeView,
    claim_translations: &ClaimTranslations,
) -> ClaimMetadata {
    let claim_schema = match claim {
        CredentialSchemaClaimsNestedTypeView::Field(claim_schema) => claim_schema,
        CredentialSchemaClaimsNestedTypeView::Object(object_claim) => &object_claim.claim,
    };

    let display = claim_translations
        .get(&claim_schema.id)
        .into_iter()
        .flatten()
        .map(|(locale, texts)| ClaimDisplay {
            locale: locale.to_owned(),
            label: texts.name.to_owned().unwrap_or_else(|| name.to_owned()),
            description: texts.description.to_owned(),
        })
        .collect();

    ClaimMetadata {
        path,
        display,
        mandatory: None,
        sd: Some(SelectiveDisclosure::Allowed),
    }
}

fn vct_simple_rendering_from_schema(
    schema: &CredentialSchema,
) -> Result<Option<SimpleRendering>, IssuerServiceError> {
    let Some(layout_properties) = &schema.layout_properties else {
        return Ok(None);
    };

    let mut result = SimpleRendering {
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
        result.logo = Some(Logo {
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
            result.background_image = Some(BackgroundImage { uri });
        }
    }

    Ok(Some(result))
}
