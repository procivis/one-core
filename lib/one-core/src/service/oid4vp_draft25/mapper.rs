use one_dto_mapper::{convert_inner, convert_inner_of_inner};

use crate::common_mapper::{get_or_create_did_and_identifier, DidRole};
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::organisation::Organisation;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VPVerifierInteractionContent, ProvedCredential,
};
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::service::error::ServiceError;

pub(super) fn parse_interaction_content(
    data: Option<&Vec<u8>>,
) -> Result<OpenID4VPVerifierInteractionContent, ServiceError> {
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
    identifier_repository: &dyn IdentifierRepository,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<Credential, ServiceError> {
    let (issuer_did, issuer_identifier) = get_or_create_did_and_identifier(
        did_method_provider,
        did_repository,
        identifier_repository,
        &Some(organisation.to_owned()),
        &proved_credential.issuer_did_value,
        DidRole::Issuer,
    )
    .await?;
    let (holder_did, holder_identifier) = get_or_create_did_and_identifier(
        did_method_provider,
        did_repository,
        identifier_repository,
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
        state: proved_credential.credential.state,
        claims: convert_inner_of_inner(proved_credential.credential.claims),
        issuer_did: Some(issuer_did),
        issuer_identifier: Some(issuer_identifier),
        holder_did: Some(holder_did),
        holder_identifier: Some(holder_identifier),
        schema: proved_credential
            .credential
            .schema
            .map(|schema| from_provider_schema(schema, organisation.to_owned())),
        interaction: None,
        revocation_list: None,
        key: proved_credential.credential.key,
        suspend_end_date: convert_inner(proved_credential.credential.suspend_end_date),
    })
}

fn from_provider_schema(schema: CredentialSchema, organisation: Organisation) -> CredentialSchema {
    CredentialSchema {
        id: schema.id,
        deleted_at: schema.deleted_at,
        created_date: schema.created_date,
        last_modified: schema.last_modified,
        name: schema.name,
        external_schema: schema.external_schema,
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
