use one_dto_mapper::{convert_inner, convert_inner_of_inner};

use crate::common_mapper::{get_or_create_did, DidRole};
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::provider::exchange_protocol::openid4vc::model::{
    OpenID4VCIInteractionDataDTO, OpenID4VPInteractionContent, ProvedCredential,
};
use crate::repository::did_repository::DidRepository;
use crate::service::error::ServiceError;

pub(crate) fn interaction_data_to_dto(
    interaction: &Interaction,
) -> Result<OpenID4VCIInteractionDataDTO, ServiceError> {
    let interaction_data = interaction
        .data
        .to_owned()
        .ok_or(ServiceError::MappingError(
            "interaction data is missing".to_string(),
        ))?;
    let json_data = String::from_utf8(interaction_data)
        .map_err(|e| ServiceError::MappingError(e.to_string()))?;

    let interaction_data_parsed: OpenID4VCIInteractionDataDTO =
        serde_json::from_str(&json_data).map_err(|e| ServiceError::MappingError(e.to_string()))?;
    Ok(interaction_data_parsed)
}

pub(super) fn parse_interaction_content(
    data: Option<&Vec<u8>>,
) -> Result<OpenID4VPInteractionContent, ServiceError> {
    if let Some(interaction_data) = data {
        serde_json::from_slice(interaction_data)
            .map_err(|e| ServiceError::MappingError(e.to_string()))
    } else {
        Err(ServiceError::MappingError(
            "Interaction data is missing or incorrect".to_string(),
        ))
    }
}

pub(super) async fn credential_from_proved(
    proved_credential: ProvedCredential,
    organisation: &Organisation,
    did_repository: &dyn DidRepository,
) -> Result<Credential, ServiceError> {
    let issuer_did = get_or_create_did(
        did_repository,
        &Some(organisation.to_owned()),
        &proved_credential.issuer_did_value,
        DidRole::Issuer,
    )
    .await?;
    let holder_did = get_or_create_did(
        did_repository,
        &Some(organisation.to_owned()),
        &proved_credential.holder_did_value,
        DidRole::Holder,
    )
    .await?;

    Ok(Credential {
        id: proved_credential.credential.id,
        created_date: proved_credential.credential.created_date,
        issuance_date: proved_credential.credential.issuance_date,
        last_modified: proved_credential.credential.last_modified,
        deleted_at: proved_credential.credential.deleted_at,
        credential: proved_credential.credential.credential,
        exchange: proved_credential.credential.exchange,
        redirect_uri: proved_credential.credential.redirect_uri,
        role: proved_credential.credential.role,
        state: convert_inner_of_inner(proved_credential.credential.state),
        claims: convert_inner_of_inner(proved_credential.credential.claims),
        issuer_did: Some(issuer_did),
        holder_did: Some(holder_did),
        schema: proved_credential
            .credential
            .schema
            .map(|schema| from_provider_schema(schema, organisation.to_owned())),
        interaction: None,
        revocation_list: None,
        key: proved_credential.credential.key,
    })
}

fn from_provider_schema(schema: CredentialSchema, organisation: Organisation) -> CredentialSchema {
    CredentialSchema {
        id: schema.id,
        deleted_at: schema.deleted_at,
        created_date: schema.created_date,
        last_modified: schema.last_modified,
        name: schema.name,
        format: schema.format,
        revocation_method: schema.revocation_method,
        wallet_storage_type: convert_inner(schema.wallet_storage_type),
        layout_type: schema.layout_type,
        layout_properties: convert_inner(schema.layout_properties),
        imported_source_url: schema.imported_source_url,
        schema_id: schema.schema_id,
        schema_type: schema.schema_type,
        claim_schemas: convert_inner_of_inner(schema.claim_schemas),
        organisation: organisation.into(),
        allow_suspension: schema.allow_suspension,
    }
}
