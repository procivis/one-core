use one_dto_mapper::{convert_inner, convert_inner_of_inner};

use crate::common_mapper::{IdentifierRole, RemoteIdentifierRelation, get_or_create_identifier};
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::organisation::Organisation;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VPVerifierInteractionContent, ProvedCredential,
};
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::key_repository::KeyRepository;
use crate::service::certificate::validator::CertificateValidator;
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn credential_from_proved(
    proved_credential: ProvedCredential,
    organisation: &Organisation,
    did_repository: &dyn DidRepository,
    certificate_repository: &dyn CertificateRepository,
    identifier_repository: &dyn IdentifierRepository,
    certificate_validator: &dyn CertificateValidator,
    did_method_provider: &dyn DidMethodProvider,
    key_repository: &dyn KeyRepository,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<Credential, ServiceError> {
    let (issuer_identifier, issuer_relation) = get_or_create_identifier(
        did_method_provider,
        did_repository,
        certificate_repository,
        certificate_validator,
        key_repository,
        key_algorithm_provider,
        identifier_repository,
        &Some(organisation.to_owned()),
        &proved_credential.issuer_details,
        IdentifierRole::Issuer,
    )
    .await?;

    let issuer_certificate =
        if let RemoteIdentifierRelation::Certificate(certificate) = issuer_relation {
            Some(certificate)
        } else {
            None
        };

    let (holder_identifier, ..) = get_or_create_identifier(
        did_method_provider,
        did_repository,
        certificate_repository,
        certificate_validator,
        key_repository,
        key_algorithm_provider,
        identifier_repository,
        &Some(organisation.to_owned()),
        &proved_credential.holder_details,
        IdentifierRole::Holder,
    )
    .await?;

    Ok(Credential {
        id: proved_credential.credential.id,
        created_date: proved_credential.credential.created_date,
        issuance_date: proved_credential.credential.issuance_date,
        last_modified: proved_credential.credential.last_modified,
        deleted_at: proved_credential.credential.deleted_at,
        protocol: proved_credential.credential.protocol,
        redirect_uri: proved_credential.credential.redirect_uri,
        role: proved_credential.credential.role,
        state: proved_credential.credential.state,
        claims: convert_inner_of_inner(proved_credential.credential.claims),
        issuer_identifier: Some(issuer_identifier),
        issuer_certificate,
        holder_identifier: Some(holder_identifier),
        schema: proved_credential
            .credential
            .schema
            .map(|schema| from_provider_schema(schema, organisation.to_owned())),
        interaction: None,
        revocation_list: None,
        key: proved_credential.credential.key,
        suspend_end_date: convert_inner(proved_credential.credential.suspend_end_date),
        profile: proved_credential.credential.profile,
        credential_blob_id: proved_credential.credential.credential_blob_id,
        wallet_unit_attestation_blob_id: proved_credential
            .credential
            .wallet_unit_attestation_blob_id,
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
